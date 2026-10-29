# Recursive-delete guard: details

How the protected-delete guard in `scripts/pretool_safety.py` reads a recursive
delete. The [README](README.md#recursive-deletes) has the summary: what is
denied, what is allowed by rule, and what goes to the LLM. This page is the
detail behind it, for anyone checking a verdict or changing the guard.

## Variables that may be empty

A recursive `rm` whose target leans on a variable that may be empty is denied
with a rewrite for the agent to run instead. `rm -rf "$T/$k"` becomes
`rm -rf /` when both are empty. Claude Code stops for manual approval on that
shape, and no hook, auto mode or bypass mode can clear that prompt. The deny
tells the agent to write `"${T:?}/${k:?}"`: the shell then aborts instead of
deleting when a value is empty, which proves the empty case away at run time,
and Claude Code runs it without asking. The rule covers targets that start with
`/`, `~`, `$VAR` or `$(…)`, and requires a guard on every variable that the
command sets or unsets itself or that is unset or empty in the environment. It
also covers `"$D"/*` and `/tmp/$k`, which Claude Code's own check lets through;
the rewrite keeps globs, brace groups and a leading `~` outside the quotes
(`"${D:?}/"*`). A
bare `rm -rf "$X"` is left alone, since an empty X deletes nothing, and so is a
`$`, glob or `~` in quotes or escaped. One guard covers later uses of the same
name, and `${X:-${Y:?}}` counts as guarded. Values that can't take a guard in
place (`$!`, `${X%/}`, `${X:+…}`, `${!X}`, a `$(…)` other than `$(pwd)`) get
"use a literal path", and so does a whole target the protected-folder guard
can't follow (`rm -rf "${HOME%/}"`; `"$@"` is exempt) and any `..` after an
expansion (`"$D/../x"`, or glued on as `"$D"../*`). A variable that can hold
`.` or `..` is refused even when guarded, if it forms a whole path component.
That covers a loop or `read` variable fed by `ls -a`/`--all` (or `ls $flags`
with `flags=-a`, a copy of it, or one inherited), a `.*` glob, a variable holding such a list, a value taken
from one (`g=$f`, `g=$(echo "$f")`), and `$1`…`${99}` or `"$@"` after
`set -- "$f"` (including `for g; do` and `for g do`). Guarded
targets still go to the LLM like any other recursive delete. The
protected-folder guard reads through `${X:?}` and the default operators
(including a `~` in the default), `$(pwd)` (unless the command redefines
`pwd`), `${X:=…}`, zsh's `${X::=…}` and `$((X=1))` assignments in any command, and
`export`/`declare`/`local` assignments, also behind `builtin` or `command` and
their flags. Anything that may not run, or runs in a subshell (inside
`if`/`while`/`for`/`case`/`{ }`, after `&&` or `||`, in `( )`, a pipeline or
an `&` job, or an arithmetic operand like `0 && (X=1)`), adds what it assigns
or `cd`s to beside the old value. Each command is followed once per directory
the command may be in, and the target is checked against each. `pushd`/`popd`
follow the directory stack and `cd -` the previous directory; once that can't be
known (an entry from before the command, `cd +1`, a stack change that may not
run, a plain `cd` under zsh's `AUTO_PUSHD`, a folder already on the stack under
`PUSHD_IGNORE_DUPS`, `setopt` or `shopt` in the command), they may go to any directory seen
so far; a bare `pushd` may also go home (`PUSHD_TO_HOME`), and pushing the
current folder again counts as a duplicate too. A `cd` to a folder that doesn't
exist (or a `cd OLD NEW` whose OLD isn't in the path, or a `cd ~-/…` that isn't
there) may fail and leave the shell where it was. What runs there: nothing after
an `|| exit [N]`/`|| return [N]` (N a number or `$?`) that ends the command (not
one piped on, and not in a command that defines, disables or aliases them, even
with a quoted name like `function "exit"` or an escaped one like `$'\x64isable'`, uses `eval`, `source` or `.`, or runs a
command whose name is expanded, like `$a$b exit`); the commands after the `&&` chain the `cd` starts (`cd x && a; rm
…` runs the `rm` either way); otherwise the next command. `set -e` isn't counted
(quoting, variables, `eval` or a function can turn it off), so the delete after a
may-fail `cd` is checked from both folders. A deny caused that way says to chain
the delete with `cd DIR && rm …`. The `cd`/`pushd`/`popd` operands are counted
after expansion: an unquoted `$X` (or `$(cmd)`) that expands to nothing is gone,
so `cd $X` goes home (a deny caused that way says to quote it; a quote inside
`${X:+"x"}` doesn't keep it), a flag is only zsh's own (`-q`, `-s`, `-L`, `-P`, `--`;
`popd` takes just `-q`) before any operand, literal or expanded (`cd -bad /tmp` and
`cd /tmp -q` are `cd OLD NEW`, which fails), `cd -s` fails when a folder its
operand names (or `cd -s -`'s previous folder) is a symlink, `cd -P` ends in the
physical folder (`link/..` is the link target's parent), an unquoted brace group is its words (`cd {A,B}` is `cd A
B`), and an unquoted `$(cmd)`, glob or `"$@"` may make any number of operands; the descriptor in `2>&1` or `{fd}>f` is not an operand.
A `cd`/`pushd` with more than two operands, or a `popd` given anything but
`+N`/`-N`, is an error that changes nothing. zsh's `cd
OLD NEW` swaps OLD for NEW in the current directory (an empty NEW removes OLD,
an empty OLD puts NEW in front; either may be a stack tilde), and `~+`, `~-` and `~N` (in a
`cd` or an `rm` target) are the current, previous and stack directories; once a
`cd` has run, `~-` in a value (`T=~-`, `for T in ~-`, `${X:-~-}`) is the tracked
previous directory too (and `~1`, `~-1`, `~+1` there any directory seen so far,
`~$N`/`~$U` there any of those or home; a
`~$N`/`~$U` delete target, named only at run time, is denied; a quoted one, `'~$U'`,
is a file by that name, but `''~$U` and `$''~$U` are not quoted; zsh's `$'…'`
is read with its escapes decoded, a NUL kept in a value as zsh keeps it but
ending a `cd` or `rm` path as the system call does, and zsh's `$"…"` is a `$` and a quoted string: `cd $"/tmp"` goes to
`$/tmp`), and `$OLDPWD` is where that `cd` came from (or, when it
may not run or may fail, what it held before). The `cd`/`pushd` operands are expanded
once, so `cd "${D::=$D/..}"` climbs once. Inside a loop, or after zsh's
`repeat N`, a relative `cd` and an assignment that reads a variable can also end
up anywhere. A body with no `;` before it is a command of its own: `for g do
rm …` (or `for f g do`), zsh's `if [[ -d x && -d y ]] rm …`, `while (( n )) { … }`, `for f (a b)
rm …` and `f() rm …`, and `function f { … }`, also after `repeat N`, `time`,
`{`, `!` or a function head (`f() { if [[ -d x ]] rm …; }`). zsh's `-`, `noglob`,
`nocorrect`, `repeat N` and `time` run the command after them, and `for f g in …`
gives each name any of the values (a loop over `ls -a` marks each name as one
that can hold `..`). A `${Z:=…}` in a list too big to follow
leaves `Z` too big to follow, so a delete that reads it is denied. A `for` loop
over a list it can follow is checked once per value, with braces expanded, globs
matched and words split where an expansion can split them (`for f in ~/*` is
denied); a word it can't follow adds an unknown value beside the rest. zsh's
brace expansion inside a default (`${X:-~/{Desktop,Documents}}`) is checked
too. A value it can't know (`X=$(cmd)`, a `read` variable, a loop over
`$(cmd)`) is checked both as some folder and as empty, each such value on its
own, also through assignments and loop lists, so `"${X:?}/../.."` still climbs to `/` and `"${X:-$HOME/Dev}"` still
reaches `~/Dev`. A target with too many paths to check (a brace expansion over
4096 words, more than 8192 loop values or mixes of values in one word, a copy
of such a value, more than 256 directories the command may be in, or more than
about a second of checking in one command) is denied with "list the targets". A target that hits a protected folder even with every such value
non-empty is denied outright; one that only an empty value would turn into a
protected folder gets the rewrite first.

## zsh and bash

All of the above is zsh's reading (the macOS default shell). Every command is
also read as bash runs it (Linux, Git Bash on Windows, or zsh with
`SH_WORD_SPLIT`), and a protected folder either reading reaches is denied. In
bash an unquoted value splits into words (`X="build $HOME/Dev"; rm -rf $X`
deletes `~/Dev`), in an `rm` target and a `for` list alike. It splits at the
characters of a literal `IFS=…` too, and once IFS is set some other way, at
any characters at all (any stretch of the value is a possible word; past 256
characters only at each one, or all its punctuation, and the LLM judges the rest). Quoted
text beside the value (`"a b"$X`), and a quoted `for` word, are never split. `$"…"` is a plain quoted string, and a
`$'…'` string ends at a NUL, so `$'\0'`, `$'\c@'` and `$'\400'` are empty. A `~` after a quote
(`''~/x`) is not home. `cd` takes only `-L`, `-P`, `-e` and `-@`, and
`pushd`/`popd` only `-n`, which doesn't change directory (though a later
`popd` may go to what `pushd -n` pushed, an expanded or split one too). Any other `-x` there, including
`cd -1`, fails and leaves the shell where it was. A second operand makes
bash 5 fail and bash 3.2 go to the first, so both are checked. An unquoted
`cd $D` whose value holds a space is its words (`D="-L $HOME"` is `cd -L
~`; an expanded `~` stays a literal name), one holding only spaces is a bare
`cd` (home), an expanded `-P` goes to the LLM, and it lands anywhere once IFS
is set. `unset IFS` and reads like `$IFS` or `${#IFS}` leave the
default. `enable -n exit` turns
the builtin off as zsh's `disable` does, and `shopt` counts like `setopt`.

In either shell, an `rm` argument whose value the guard can work out and that
turns out to be a flag (`F=-rf; rm $F ~/Dev`, or bash's `X="-rf ~/Dev"; rm
$X` and `F="r ~/Dev"; rm -$F`) makes the delete recursive; past `--` it is a
name. Once options are set (`setopt`, `shopt`), a `cd NAME` with no `NAME`
folder there may also go to `$NAME` (CDABLE_VARS). When the command sets
`CDPATH` (or the environment has it), a relative `cd NAME` may also go to
each of its folders' `NAME`, and it fails only when none of them exists;
zsh's `cdpath=(…)` array isn't followed, so there it lands anywhere.

## Scratch deletes allowed by rule

Two kinds of recursive `rm` are allowed by rule, because they only clear
scratch space: a folder at least one level below `/tmp` or `/private/tmp`
(`rm -rf /tmp/build-1`, not `/tmp` itself), and a Python, pytest, mypy, ruff
or Dart cache (`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`,
`.dart_tool`) inside the working directory, when that directory and the cache,
as written and with symlinks resolved, are under a `safe_write_paths` folder
other than `/var/folders`. Every target has to be spelled out: no `$`, glob,
brace, `..`, space or flag from a variable, and no `cd` to a variable earlier
in the command. A symlink is followed (`/tmp/link/sub` with `link` → `/usr` is
not scratch). Because a command earlier in the same call could plant a link
(`ln -s ~ /tmp/x && rm -rf /tmp/x/Documents`), a temp path deeper than
`/tmp/NAME`, a cache in a subfolder, or a target ending in `/`, counts only
when every other command in the call is one that can't create or move a link
(`ls`, `mkdir`, `echo`, `cd`, `grep`, …), named plainly and with no way to
change which program a name runs (`./mkdir`, `export`, `printf -v` and a call
that mentions `PATH` don't count). `/var/folders`, `build`, `dist`, `node_modules` and `target` are
not on the list, and one target off the list sends the whole delete to the LLM.
The protected-folder deny still comes first.

## Known limits

Known limits: the guard models plain shell, not deliberate obfuscation. A
`cd` flag that comes from a variable (`F=-P; cd $F link`), a brace group
holding `${…}` in a `cd` operand (`cd {/tmp,${HOME}/x}`), a brace-spelled
builtin (`di{s,s}able exit`, `e{x,x}it() …`) or a nested `~${U:-${V}}` can
put the shell somewhere the guard doesn't follow. None of these is
auto-allowed: they reach the LLM like any other recursive delete.
