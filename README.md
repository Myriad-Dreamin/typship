# typship

**`Pack`: a concept weaker than a package — move Typst packs across directories, tarballs, GitHub repos/subtrees/releases, and `@preview` / `@local` registries.**

- **Homepage & Interactive Pack Stage**: <https://myriad-dreamin.github.io/typship/>
- **Pack Guide & Shape Reference**: <https://myriad-dreamin.github.io/typship/guide.html>

---

## Core Concept: `Pack` ⊃ `Package`

A formal Typst **Package** requires a complete `typst.toml` manifest and a registered `@namespace/name:version` identity. **`typship` introduces `Pack` — a strictly weaker concept**:

- Any file tree (with or without `typst.toml`), a subdirectory inside a GitHub repository, a `.tar.gz` archive, a GitHub Release asset, or a `@preview` / `@local` package is a **Pack**.
- `typship` auto-detects both the **Source Pack** container and the **Destination Pack** container by shape, strips outer wrappers (`.git`, single-child directory chains up to 3 levels), locates the pack root when `typst.toml` is present (or preserves the directory structure as-is when absent), and places the result atomically.

```text
Source Pack Container  ──(strip & locate root)──▶  Normalized Pack Tree  ──(atomic stage & place)──▶  Dest Pack Container
```

---

## Features & CLI Usage

`typship` provides four orthogonal subcommands around the `Pack` abstraction:

### 1. `typship init` — Initialize a package skeleton

Generates `typst.toml` (serialized via the `toml` crate), `lib.typ`, and `src/lib.typ` in the current empty directory. Refuses to overwrite non-empty directories.

```bash
mkdir my-notes && cd my-notes
typship init
```

### 2. `typship copy [flags] <SRC> <DST>` — Copy a Pack across any Source & Destination shape

Auto-detects `<SRC>` and `<DST>` by shape and materializes the Pack into the destination atomically:

```bash
# GitHub subdirectory (supports branch names containing '/') -> local directory
typship copy https://github.com/typst/templates/tree/main/charged-ieee ./ieee

# Manifest-less local directory (Weaker Pack) -> deterministic sorted ustar .tar.gz (mode 0644/0755, mtime=0)
typship copy ./draft-notes ./dist/draft-notes.tar.gz

# @preview / @local / custom registry -> local directory
typship copy @preview/cetz:0.3.2 ./vendor/cetz

# Local pack -> GitHub Release (creates the release on 404 and uploads the .tar.gz asset)
GITHUB_TOKEN=ghp_... typship copy ./my-pack https://github.com/owner/my-pack/releases/v0.1.0
```

| Source Pack `<SRC>` Shapes | Destination Pack `<DST>` Shapes |
| :--- | :--- |
| `-` (stdin `.tar.gz` stream) | Local directory path (staged in an adjacent temp dir on the same mount + atomic `rename`) |
| Local directory or `*.tar.gz` / `*.tgz` file | `*.tar.gz` / `*.tgz` archive (deterministic `walkdir`-sorted `ustar`, `mtime = 0`) |
| `@preview/name[:ver]`, `@local/name[:ver]`, `@ns/name[:ver]` | `https://github.com/<owner>/<repo>/releases/[tag/]<tag>` (via `GITHUB_TOKEN` / `TYPSHIP_TOKEN`) |
| `github.com/<owner>/<repo>[.git]`, `tree/<ref>[/<subpath>]`, `releases/latest`, `releases/tag/<tag>` | |
| Direct `http(s)://.../*.tar.gz` URL or bare `name[:ver]` | |

### 3. `typship link [flags] <SRC> <DST>` — Symlink local Packs with remote fallback

Creates a directory symlink (or Windows junction fallback) when `<SRC>` is a local directory (`Source::Fs` or `@local/...`) and `<DST>` is a directory; automatically falls back to `typship copy` when `<SRC>` is remote or an archive.

```bash
typship link ./my-pack ./project/vendor/my-pack
typship link @local/shared-theme ./slides/theme
```

### 4. `typship download [flags] <SPEC>` — Populate the local cache

Fetches a package into `~/.local/share/typship/packages/<name>@<version>` (or `$TYPSHIP_PACKAGES_DIR`).

```bash
typship download cetz:0.3.2
typship download @preview/cetz
```

---

## Installation

Requires **Rust 1.85+** (Edition 2024).

```bash
cargo install --git https://github.com/Myriad-Dreamin/typship typship
```

Or build and test from source:

```bash
git clone https://github.com/Myriad-Dreamin/typship.git
cd typship
cargo build --release --workspace
cargo test --workspace
```

> **Note:** Earlier `typship 0.1.0–0.4.2` releases on crates.io belong to the legacy pre-refactor line. Install from Git to use the current `typship-pack` architecture.

---

## Workspace Architecture

- **`crates/typship`**: Thin CLI entry (`palc` argument parser, `init` skeleton generator, `download` cache command).
- **`crates/typship-pack`**: Library implementing the named `Pack` abstraction (`fs`, `http`, `source`, `dest`, `transport`, `github`, `copy`).

## License

MIT License.
