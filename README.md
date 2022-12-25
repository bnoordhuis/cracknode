To all you people complaining `node` doesn't run on your ancient distro:

**Stop gacking, start cracking!**

Here is what it does:

1. `cracknode` patches out newer glibc symbols from the `node` executable

2. `hacknode` adds runtime support for the goodies old systems lack

Run at your own risk. As the ancient proverb goes: THE SOFTWARE IS PROVIDED
"AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES.

Prerequisites:

1. x86_64 linux
2. gcc or clang

Build & apply:

    # run this once
    $ make

    # also run this once and make sure node is writable
    $ ./cracknode `which node`

    # invoke node like so from now on
    $ ./hacknode node -p 'console.log("Hello, crackers!")'

For the UNIX connaisseurs among you: observe how `hacknode` is an executable
that's also a `LD_PRELOAD` shared library. A certain amount of pitch black
sorcery is involved in making it all work.
