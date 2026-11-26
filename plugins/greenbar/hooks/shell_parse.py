"""Shell reading for the greenbar guard. Python 3.9+, standard library only.

Turns a command line into the simple commands it would really run, so the guard judges
`cat .env` the same whether it is typed bare, behind `timeout 30`, inside `bash -c '...'`,
in a pipe, a subshell, a loop body or `$(...)`.

  lex()    splits text into words, operators and redirections with quotes and escapes
           removed (so `c\\at`, "cat" and /bin/cat are all `cat`), and collects the text
           inside `$(...)`, backticks, `<(...)` and unquoted here-documents.
  parse()  groups those into commands, drops keywords (`if`, `do`, `!`, `{`), follows
           `cd`, fills in variables set to plain text earlier on the line, unwraps
           wrapper commands (`sudo`, `env`, `timeout`, `nice`, `xargs`, ...) and returns
           any command strings that will be run (`sh -c`, `eval`, text piped to a shell).

It reads text; it does not run anything. See README, "What it does not do".
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

Token = Tuple[str, str, str]  # ("word", text, "") | ("op", operator, "") | ("redir", operator, target)

REDIRECT = re.compile(r"&>>|&>|>>|>\||>&|<<<|<<-|<<|<&|<>|>|<")
OPERATORS = (";;&", "&&", "||", ";;", ";&", "|&", ";", "|", "&", "(", ")")
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", "<>", ">&"}
PLACEHOLDER = "$__substitution__"  # stands in for text only known at run time
ASSIGN = re.compile(r"[A-Za-z_]\w*\+?=")
VARIABLE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
BRACES = re.compile(r"\{([^{}]*,[^{}]*)\}")
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!",
            "esac", "coproc", "function"}
DECLARERS = {"export", "local", "declare", "typeset", "readonly"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh", "mksh", "rbash",
          "pdksh", "ksh93", "yash"}
STRING_FLAG_RUNNERS = SHELLS | {"su", "runuser", "script", "flock"}  # `-c 'command string'`
STDIN_NAMES = {"-", "/dev/stdin"}
IFS = re.compile(r"\$\{IFS[^}]*\}|\$IFS(?!\w)")
EMPTY = re.compile(r"\$[@*1-9]|\$\{[@*1-9]\}")  # no arguments in a fresh shell: these expand to nothing
DEFAULT = re.compile(r"\$\{(\w+):?[-=]([^{}]*)\}")  # ${name:-fallback}
MAX_BRACE_STEPS = 2000


def program(word: str) -> str:
    """The program a command word names: /bin/cat, CAT (macOS) and =cat (zsh) are all `cat`."""
    return os.path.basename(word).lower().lstrip("=")


def _wrappers() -> Dict[str, Tuple[frozenset, int]]:
    """name -> (options that take a separate value, plain words before the wrapped command)."""
    table = {
        "sudo doas": "-u -g -C -p -U -h -r -t -T -D -R --user --group --chdir --prompt --host --role --type",
        "env": "-u -C --unset --chdir",
        "command builtin nohup setsid chronic unbuffer busybox toybox noglob nocorrect": "",
        "exec": "-a",
        "time gtime": "-f -o --format --output",
        "nice gnice": "-n --adjustment",
        "ionice": "-c -n -p -P -u --class --classdata",
        "timeout gtimeout": "-s -k --signal --kill-after",
        "stdbuf gstdbuf": "-i -o -e --input --output --error",
        "caffeinate": "-t -w",
        "xargs gxargs": "-n -P -I -L -s -E -d -a -J -R -S --max-args --max-procs --max-lines "
                        "--max-chars --delimiter --arg-file --eof",
        "watch": "-n --interval",
        "arch": "-arch -e",
        "strace ltrace dtruss": "-e -o -p -s -u -a -E -P -b -I -S -U -X",
        "flock": "-w -E --timeout --conflict-exit-code",
        "chrt taskset chroot": "",
    }
    leading_words = {"timeout": 1, "gtimeout": 1, "flock": 1, "chrt": 1, "taskset": 1, "chroot": 1}
    return {name: (frozenset(flags.split()), leading_words.get(name, 0))
            for names, flags in table.items() for name in names.split()}


WRAPPERS = _wrappers()


class Command:
    """One simple command: the program and arguments that would run, and where."""

    def __init__(self, argv: List[str], cwd: str, redirects: Optional[List[Tuple[str, str]]] = None,
                 assigns: Optional[List[str]] = None, stdin: Optional[str] = None,
                 derived: bool = False, cwd_known: bool = True,
                 wrapper_words: Optional[List[str]] = None) -> None:
        self.argv = argv
        self.cwd = cwd
        self.cwd_known = cwd_known  # False after `cd $SOMEWHERE`, `cd -` or `popd`
        self.wrapper_words = wrapper_words or []  # words of stripped wrappers (`xargs -a FILE`)
        self.redirects = redirects or []
        self.assigns = assigns or []
        self.stdin = stdin      # text fed on standard input, when the command line spells it out
        self.derived = derived  # found inside another command's arguments, not at its head

    @property
    def name(self) -> str:
        return program(self.argv[0]) if self.argv else ""

    def file_redirects(self, writes_only: bool = False) -> List[str]:
        return [target for op, target in self.redirects
                if op not in ("<<", "<<<") and not (target.isdigit() or target == "-")
                and (op in WRITE_REDIRECTS or not writes_only)]


# ---------- lexer ----------

class Lexer:
    def __init__(self, text: str, start: int = 0, closing: bool = False) -> None:
        self.s, self.i = text, start
        self.closing, self.depth, self.done = closing, 0, False  # closing: stop at the unmatched ")"
        self.buf: Optional[List[str]] = None
        self.quoted = False
        self.pending: Optional[str] = None
        self.heredocs: List[Tuple[int, str, bool, bool]] = []
        self.tokens: List[Token] = []
        self.nested: List[Tuple[int, str]] = []  # (index of the token it sits in, command text)
        self.unbalanced = False

    def add(self, text: str) -> None:
        if self.buf is None:
            self.buf = []
        self.buf.append(text)

    def flush(self) -> None:
        if self.buf is None:
            return
        word, self.buf = "".join(self.buf), None
        quoted, self.quoted = self.quoted, False
        op, self.pending = self.pending, None
        if op is None:
            self.tokens.append(("word", word, ""))
        elif op in ("<<", "<<-"):
            self.heredocs.append((len(self.tokens), word, op == "<<-", quoted))
            self.tokens.append(("redir", "<<", ""))
        else:
            self.tokens.append(("redir", op, word))

    def run(self) -> Lexer:
        s, n = self.s, len(self.s)
        while self.i < n and not self.done:
            c = s[self.i]
            if c == "\\":
                self.quoted = True
                if self.i + 1 < n and s[self.i + 1] != "\n":
                    self.add(s[self.i + 1])
                self.i += 2
            elif c == "'":
                self.single_quoted(self.i + 1)
            elif c == '"':
                self.double_quoted()
            elif c == "`":
                self.backtick()
            elif c == "$" and s.startswith("$(", self.i):
                self.substitution(self.i + 2)
            elif c == "$" and EMPTY.match(s, self.i):
                self.add("")
                self.i = EMPTY.match(s, self.i).end()
            elif c == "$" and IFS.match(s, self.i):
                self.flush()  # `cat${IFS}.env`: the shell splits here like a space
                self.i = IFS.match(s, self.i).end()
            elif c == "$" and s.startswith("$'", self.i):
                self.ansi_c_quoted()
            elif c == "$" and s.startswith('$"', self.i):
                self.i += 1
            elif c in "<>" and s.startswith("(", self.i + 1):
                self.substitution(self.i + 2)
            elif c in " \t\r":
                self.flush()
                self.i += 1
            elif c == "\n":
                self.newline()
            elif c == "#" and self.buf is None:
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end
            else:
                self.operator_or_char()
        self.flush()
        return self

    def single_quoted(self, start: int) -> None:
        end = self.s.find("'", start)
        if end < 0:
            self.unbalanced, end = True, len(self.s)
        self.quoted = True
        self.add(self.s[start:end])
        self.i = end + 1

    def ansi_c_quoted(self) -> None:
        s, n, j = self.s, len(self.s), self.i + 2
        while j < n and s[j] != "'":
            j += 2 if s[j] == "\\" else 1
        raw = s[self.i + 2:j]
        try:
            text = raw.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except (UnicodeError, ValueError):
            text = raw
        self.quoted = True
        self.add(text)
        self.i = j + 1

    def double_quoted(self) -> None:
        s, n = self.s, len(self.s)
        self.quoted = True
        self.add("")
        self.i += 1
        while self.i < n and s[self.i] != '"':
            c = s[self.i]
            if c == "\\" and self.i + 1 < n and s[self.i + 1] in '$`"\\\n':
                if s[self.i + 1] != "\n":
                    self.add(s[self.i + 1])
                self.i += 2
            elif c == "$" and s.startswith("$(", self.i):
                self.substitution(self.i + 2)
            elif c == "$" and EMPTY.match(s, self.i):
                self.i = EMPTY.match(s, self.i).end()
            elif c == "`":
                self.backtick()
            else:
                self.add(c)
                self.i += 1
        if self.i >= n:
            self.unbalanced = True
        self.i += 1

    def backtick(self) -> None:
        s, n, j = self.s, len(self.s), self.i + 1
        while j < n and s[j] != "`":
            j += 2 if s[j] == "\\" else 1
        text = s[self.i + 1:j].replace("\\`", "`")
        self.nested.append((len(self.tokens), text))
        self.add("$PWD" if text.strip() == "pwd" else PLACEHOLDER)
        self.i = j + 1

    def substitution(self, start: int) -> None:
        """`$(...)`, `<(...)`, `>(...)`: the text inside is a command of its own."""
        inner = Lexer(self.s, start, closing=True).run()
        self.unbalanced = self.unbalanced or inner.unbalanced
        text = self.s[start:inner.i]
        body = text.strip()
        arithmetic = (self.s[start - 2:start] == "$(" and body.startswith("(") and body.endswith(")")
                      and Lexer(body, 1, closing=True).run().i == len(body) - 1)
        if arithmetic:  # $((1 + 2)): numbers, though it may still hold a $(...) of its own
            self.nested.extend((len(self.tokens), found) for found in embedded(body[1:-1]))
        else:
            self.nested.append((len(self.tokens), text))
        self.add("$PWD" if body == "pwd" else PLACEHOLDER)
        self.i = inner.i + 1

    def newline(self) -> None:
        self.flush()
        self.pending = None
        self.tokens.append(("op", "\n", ""))
        self.i += 1
        s, n = self.s, len(self.s)
        for index, delimiter, strip_tabs, quoted in self.heredocs:
            lines: List[str] = []
            closed = False
            while self.i < n and not closed:
                end = s.find("\n", self.i)
                end = n if end < 0 else end
                line = s[self.i:end]
                self.i = min(end + 1, n)
                closed = (line.lstrip("\t") if strip_tabs else line) == delimiter
                if not closed:
                    lines.append(line)
            body = "\n".join(lines)
            self.tokens[index] = ("redir", "<<", body)
            if not closed:  # no end marker: perhaps not a here-document at all (`((x = 1 << 2))`)
                self.nested.append((index, body))
            elif not quoted:  # the shell expands $(...) and backticks in an unquoted here-document
                self.nested.extend((index, text) for text in embedded(body))
        self.heredocs = []

    def operator_or_char(self) -> None:
        s = self.s
        match = REDIRECT.match(s, self.i)
        if match:
            if self.buf is not None and "".join(self.buf).isdigit():
                self.buf = None  # a file-descriptor number, as in 2>file
            self.flush()
            self.pending = match.group()
            self.i = match.end()
            return
        for op in OPERATORS:
            if s.startswith(op, self.i):
                if self.closing and op == ")" and self.depth == 0:
                    self.done = True
                    return
                self.depth += 1 if op == "(" else -1 if op == ")" else 0
                self.flush()
                self.pending = None
                self.tokens.append(("op", op, ""))
                self.i += len(op)
                return
        self.add(s[self.i])
        self.i += 1


def embedded(text: str) -> List[str]:
    """Command substitutions inside text that the shell expands like a double-quoted string."""
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
        elif text.startswith("$(", i):
            inner = Lexer(text, i + 2, closing=True).run()
            out.append(text[i + 2:inner.i])
            i = inner.i + 1
        elif text[i] == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i + 1:j])
            i = j + 1
        else:
            i += 1
    return out


def braces(word: str, limit: int = 64) -> List[str]:
    """The word itself plus what `a{b,c}` brace expansion would turn it into."""
    out, todo, steps = [word], [word], 0
    while todo:
        steps += 1
        if steps > MAX_BRACE_STEPS or len(out) > limit:
            raise ValueError("too many brace expansions to check")
        current = todo.pop(0)
        match = BRACES.search(current)
        if not match:
            if current not in out:
                out.append(current)
            continue
        todo[:0] = [current[:match.start()] + alt + current[match.end():] for alt in match.group(1).split(",")]
    return out


# ---------- wrappers and command strings ----------

def unwrap(argv: List[str], stdin: Optional[str]) -> Tuple[List[str], List[str], List[str]]:
    """Strip wrapper commands off the front.

    Returns (what really runs, command strings to check, the wrapper words that were stripped).
    """
    strings: List[str] = []
    dropped: List[str] = []
    for _ in range(16):
        name = program(argv[0]) if argv else ""
        if name not in WRAPPERS or (name == "command" and argv[1:2] and argv[1] in ("-v", "-V")):
            break
        value_flags, leading_words = WRAPPERS[name]
        i, split = 1, None
        while i < len(argv) and split is None:
            word = argv[i]
            if word == "--":
                i += 1
                break
            if (ASSIGN.match(word) and name in ("env", "sudo", "doas")) or (name == "env" and word == "-"):
                i += 1
            elif not word.startswith("-") or word == "-":
                break
            elif name == "env" and word.startswith(("-S", "--split-string")):
                inline = word[2:] if word.startswith("-S") else word.partition("=")[2]
                split = " ".join(([inline] if inline else []) + argv[i + 1:])
            else:  # `-u root`, and clusters such as `-nu root` whose last letter takes a value
                takes_value = word in value_flags or (
                    not word.startswith("--") and len(word) > 2 and "-" + word[-1] in value_flags)
                i += 2 if takes_value else 1
        if split is not None:  # env -S 'a whole command line'
            return [], strings + [split], dropped + argv[1:i]
        rest = argv[i + leading_words:]
        if not rest:
            if name == "env":
                argv = ["env"]  # nothing to run: env prints the environment
            break
        dropped += argv[1:i + leading_words]
        if name == "watch":  # watch hands its words to `sh -c`
            return [], strings + [" ".join(rest)], dropped
        if name in ("xargs", "gxargs") and stdin:
            rest = rest + stdin.replace("\0", " ").split()
        argv = rest
    return argv, strings, dropped


def run_strings(argv: List[str], stdin: Optional[str]) -> List[str]:
    """Command text that this command will hand to a shell."""
    name = program(argv[0]) if argv else ""
    args = argv[1:]
    if name == "eval":
        return [" ".join(args)]
    if name == "trap":
        return [w for w in args[:2] if not w.startswith("-")][:1]
    if name in ("source", ".") and stdin and args[:1] and args[0] in STDIN_NAMES:
        return [stdin]
    if name not in STRING_FLAG_RUNNERS:
        return []
    for i, word in enumerate(args):
        if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*|--command", word) and i + 1 < len(args):
            return [args[i + 1]]
        if word.startswith("--command="):
            return [word.partition("=")[2]]
    script = shell_script(argv)
    reads_stdin = script is None or script in STDIN_NAMES or any(
        re.fullmatch(r"-[A-Za-z]*s[A-Za-z]*", w) for w in args)
    if name in SHELLS and stdin and reads_stdin:
        return [stdin]
    return []


def shell_script(argv: List[str]) -> Optional[str]:
    """The script file a `bash file.sh` style command runs, if any."""
    skip = False
    for word in argv[1:]:
        if skip:
            skip = False
        elif word in ("-o", "-O", "+o", "+O", "--rcfile", "--init-file"):
            skip = True
        elif word == "-" or not word.startswith(("-", "+")):
            return word
    return None


def exec_clauses(argv: List[str]) -> List[List[str]]:
    """The commands in `find ... -exec CMD ;` (also -execdir, -ok, -okdir)."""
    out: List[List[str]] = []
    i = 0
    while i < len(argv):
        if argv[i] in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            while j < len(argv) and argv[j] not in (";", "+"):
                j += 1
            if j > i + 1:
                out.append(argv[i + 1:j])
            i = j
        i += 1
    return out


# ---------- parser ----------

def unescape(text: str) -> str:
    """Backslash escapes as `printf` and `echo -e` print them (\\x2e, \\056, \\n)."""
    try:
        return text.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except (UnicodeError, ValueError):
        return text


class Parser:
    def __init__(self, cwd: str, variables: Optional[Dict[str, str]], plain: frozenset,
                 sensitive: frozenset) -> None:
        self.cwd = cwd
        self.cwd_known = True
        self.variables = dict(variables or {})
        self.plain, self.sensitive = plain, sensitive
        self.commands: List[Command] = []
        self.strings: List[Tuple[str, str, Dict[str, str]]] = []  # (text, cwd, variables)
        self.previous: Optional[Command] = None

    def fill(self, words: List[str]) -> List[str]:
        """Replace $name with text assigned earlier on the line (`f=.env; cat $f`)."""
        out: List[str] = []
        for word in words:
            whole = VARIABLE.fullmatch(word)
            key = (whole.group(1) or whole.group(2)) if whole else None
            if key is not None and key in self.variables:
                out.extend(self.variables[key].split() or [""])
                continue
            word = DEFAULT.sub(lambda m: self.variables.get(m.group(1), m.group(2)), word)
            out.append(VARIABLE.sub(
                lambda m: self.variables.get(m.group(1) or m.group(2), m.group(0)), word))
        return out

    def remember(self, assignments: List[str]) -> None:
        for text in assignments:
            name, _, value = text.partition("=")
            if "$" in value or "`" in value:
                self.variables.pop(name.rstrip("+"), None)  # not knowable from the text
            elif name.endswith("+"):
                self.variables[name[:-1]] = self.variables.get(name[:-1], "") + value
            else:
                self.variables[name] = value

    def stdin_text(self, redirects: List[Tuple[str, str]], piped: bool) -> Optional[str]:
        for op, target in reversed(redirects):
            if op in ("<<", "<<<"):
                return target
        prev = self.previous
        if not piped or prev is None:
            return None
        if prev.name in ("echo", "printf"):
            flags = [w for w in prev.argv[1:] if re.fullmatch(r"-[neE]+", w)]
            text = " ".join(w for w in prev.argv[1:] if w not in flags)
            return unescape(text) if prev.name == "printf" or any("e" in f for f in flags) else text
        if prev.name == "cat" and len(prev.argv) == 1:
            return prev.stdin
        return None

    def spread(self, words: List[str]) -> List[str]:
        """`{cat,.env}` is two words to the shell."""
        out: List[str] = []
        for word in words:
            out += braces(word)[1:] or [word] if BRACES.search(word) else [word]
        return out

    def add(self, words: List[str], redirects: List[Tuple[str, str]], piped: bool) -> None:
        while words and words[0] in KEYWORDS:
            words = words[1:]
        assigns: List[str] = []
        while words and ASSIGN.match(words[0]):
            assigns.append(words[0])
            words = words[1:]
        assigns, words = self.fill(assigns), self.spread(self.fill(words))
        redirects = [(op, target if op == "<<" else "".join(self.fill([target])[:1]) or target)
                     for op, target in redirects]
        if words and "$" in words[0] and VARIABLE.sub("", words[0]):
            words[0] = VARIABLE.sub("", words[0])  # `c${nothing}at`: an unset variable is empty
        inner_vars = dict(self.variables)  # what a nested `sh -c` would see: FOO=x sh -c '...$FOO'
        if not words:
            self.remember(assigns)
        elif program(words[0]) in DECLARERS:
            self.remember([w for w in words[1:] if ASSIGN.match(w)])
        elif words[0] == "for" and len(words) > 2 and words[2] == "in":
            self.variables[words[1]] = " ".join(words[3:])
        for text in assigns + [w for w in words[1:] if ASSIGN.match(w)]:
            name, _, value = text.partition("=")
            if "$" not in value and "`" not in value:
                inner_vars[name.rstrip("+")] = value
        stdin = self.stdin_text(redirects, piped)
        argv, strings, dropped = unwrap(words, stdin)
        main = Command(argv, self.cwd, redirects, assigns, stdin, cwd_known=self.cwd_known,
                       wrapper_words=dropped)
        found = [main]
        head = program(words[0]) if words else ""
        if head and (head in WRAPPERS or head not in self.plain):
            # An unknown program may run its arguments (`flock f cat .env`, `docker exec c rm -rf /`).
            for i in range(1, len(words)):
                if program(words[i]) in self.sensitive and words[i:] != argv:
                    inner, more, _ = unwrap(words[i:], None)
                    strings += more
                    found.append(Command(inner, self.cwd, derived=True, cwd_known=self.cwd_known))
        strings += run_strings(words, stdin)
        for cmd in list(found):
            if cmd.argv is not words:
                strings += run_strings(cmd.argv, cmd.stdin)
            for clause in exec_clauses(cmd.argv) if cmd.name == "find" else []:
                inner, more, _ = unwrap(clause, None)
                strings += more + run_strings(inner, None)
                found.append(Command(inner, self.cwd, cwd_known=self.cwd_known))
        self.commands += found
        self.strings += [(text, self.cwd, inner_vars) for text in strings if text.strip()]
        self.previous = main
        if main.name in ("cd", "pushd", "popd"):
            self.change_dir(main.name, main.argv[1:])

    def change_dir(self, name: str, args: List[str]) -> None:
        targets = [w for w in args if not w.startswith("-")]
        if name == "cd" and not args:
            self.cwd = os.path.expanduser("~")
            return
        target = re.sub(r"\$\{?HOME\}?(?!\w)", lambda _m: os.path.expanduser("~"), targets[0]) if targets else ""
        if name == "popd" or not targets or "$" in target:
            self.cwd_known = False  # `cd -`, `popd`, `cd $SOMEWHERE`: no longer sure where we are
            return
        target = os.path.expanduser(target)
        self.cwd_known = self.cwd_known or os.path.isabs(target)
        self.cwd = os.path.realpath(os.path.join(self.cwd, target))


def parse(text: str, cwd: str, variables: Optional[Dict[str, str]], plain: frozenset,
          sensitive: frozenset) -> Tuple[List[Command], List[Tuple[str, str, Dict[str, str]]], bool]:
    """Returns (commands, [(nested command text, cwd, variables)], quotes were unbalanced)."""
    lexer = Lexer(text).run()
    parser = Parser(cwd, variables, plain, sensitive)
    saved: List[Tuple[str, bool]] = []
    words: List[str] = []
    redirects: List[Tuple[str, str]] = []
    piped, last_op = False, ""
    nested = sorted(lexer.nested)
    for index, (kind, value, target) in enumerate([*lexer.tokens, ("op", "\n", "")]):
        if kind == "word":
            words.append(value)
        elif kind == "redir":
            redirects.append((value, target))
        else:
            if words or redirects:
                parser.add(words, redirects, piped)
                words, redirects = [], []
            while nested and nested[0][0] < index:  # substitutions run where they are written
                parser.strings.append((nested.pop(0)[1], parser.cwd, dict(parser.variables)))
            if value == "(":
                saved.append((parser.cwd, parser.cwd_known))
            elif value == ")" and saved:
                parser.cwd, parser.cwd_known = saved.pop()  # a subshell's `cd` ends with it
            last_op = value
        piped = last_op in ("|", "|&")
    parser.strings += [(text, parser.cwd, dict(parser.variables)) for _, text in nested]
    return parser.commands, parser.strings, lexer.unbalanced
