# typship

**From any Source, to any Destination.**

Move Typst **Packs** (a concept weaker than a package — with or without `typst.toml`) across local directories, `.tar.gz` archives, GitHub repos/subdirectories/releases, and `@preview` / `@local` registries.

- **Homepage**: <https://myriad-dreamin.github.io/typship/>
- **Guide**: <https://myriad-dreamin.github.io/typship/guide.html>

## Quick Start

```bash
# 1. Initialize a package skeleton in an empty directory
mkdir my-notes && cd my-notes && typship init

# 2. Copy a Pack from any Source to any Destination
typship copy https://github.com/typst/templates/tree/main/charged-ieee ./ieee
typship copy ./draft-notes ./dist/draft-notes.tar.gz
typship copy @preview/cetz:0.3.2 ./vendor/cetz
GITHUB_TOKEN=ghp_... typship copy ./my-pack https://github.com/owner/my-pack/releases/v0.1.0

# 3. Symlink a local Pack (falls back to copy for remote sources)
typship link @local/shared-theme ./slides/theme

# 4. Download a package into the local cache
typship download cetz:0.3.2
```

## Installation

```bash
cargo install --git https://github.com/Myriad-Dreamin/typship typship
```

## License

MIT
