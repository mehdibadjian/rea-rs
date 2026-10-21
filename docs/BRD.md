# Business Requirements Document (BRD)

**Project Name:** rea-rs (Agentic Clean-Room Modernization & Interoperability Studio)
**Target Architecture:** Single-Binary Native Rust Orchestrator (Rust 2024 Edition + Tokio + Ratatui + rmcp)
**Document Version:** 2.0 (Rust Native Edition)
**Status:** Ready for Workspace Initialization

---

## 1. Executive Summary

Legacy binary modernization, third-party security auditing, and clean-room interoperability engineering require coordinating disjointed static analyzers, bytecode unpackers, dynamic trace runners, and network inspectors. Existing Node.js/Python orchestration wrappers introduce runtime overhead, fragile dependency chains, and poor memory bounds when streaming massive disassembly dumps or execution traces into LLM context windows.

rea-rs is a zero-dependency, single-binary Rust orchestrator, Model Context Protocol (MCP) router, and terminal studio (`rea loop --watch`). It performs instant in-memory binary triage using native Rust crates, exposes a high-throughput MCP multiplexing hub to AI coding agents (Claude Code, Codex, Cursor), and enforces a strict Clean-Room Information Wall across the six-stage engineering pipeline.

## 2. Business Objectives & Engineering Goals

- **Zero-Runtime Portability:** Compile into a single statically-linked native executable (`rea`) with zero Node.js, Bun, or Python runtime prerequisites for the core engine.
- **Native In-Process Triage:** Replace slow external subprocess calls for initial binary inspection with native Rust parsing (`goblin`, `object`, `capstone`, `yara-x`) for sub-millisecond PE, ELF, Mach-O, DEX, and WebAssembly header/symbol extraction.
- **Strict Clean-Room Separation (OS-Enforced):** Prevent copyright contamination or literal decompiler translation by isolating the Analysis Agent (which reads binary artifacts and writes `rebuild/SPEC.md`) from the Rebuild Agent (which is sandboxed via filesystem namespaces to only access `rebuild/SPEC.md` and black-box test vectors).
- **Deterministic Differential Verification ("The Oracle"):** Run original legacy binaries and newly compiled clean-room builds side-by-side inside isolated sandboxes (bubblewrap / Docker / Windows Job Objects), diffing standard I/O, file mutations, exit codes, and syscall traces to calculate real-time behavioral parity.
- **60-FPS Retro Studio TUI:** Deliver the `REA.EXE STUDIO` terminal experience using `ratatui`, displaying live MCP tool hops, token burn rate, active module status (01–20), and the 6-stage parity progress bar.

## 3. Core Rust Technical Stack

| Layer | Rust Crates / Technologies | Architectural Responsibility |
|---|---|---|
| Async Runtime & IPC | `tokio`, `tokio-util`, `futures` | Multiplexing concurrent MCP servers, managing non-blocking child processes, and enforcing strict I/O ring-buffer limits. |
| MCP Server & Client Hub | `rmcp` (or custom JSON-RPC 2.0 over stdio/SSE), `serde`, `serde_json`, `schemars` | Exposing rea as an unified MCP server to Claude Code while acting as an upstream MCP client/aggregator for external bridges (GhidraMCP, ida-pro-mcp). |
| Native Binary Triage | `object`, `goblin`, `capstone`, `pdb`, `gimli` (DWARF), `zip` | Zero-subprocess parsing of ELF, PE, Mach-O, COFF, APK/ZIP structures, import/export tables, DWARF/PDB symbols, and inline disassembly. |
| Terminal Studio UI | `ratatui`, `crossterm`, `tui-logger` | Rendering the 20-module grid, embedded agent activity stream, token counter, and `BINARY -> RETRY` progress bar. |
| State & Artifact Store | `rusqlite` (bundled SQLite) or `redb`, `blake3` | Content-addressed caching (`.rea/store.db`) of decompiled functions, call graphs, SPEC.md revisions, and Oracle pass telemetry. |
| Sandbox & Oracle Isolation | `bollard` (Docker API), `nix` / `bwrap` (Linux namespaces) | Executing untrusted or legacy target binaries alongside rebuilt binaries in ephemeral, network-restricted sandboxes. |
| CLI & Configuration | `clap` (derive), `toml`, `tracing` | Handling `rea init`, `rea doctor`, `rea mcp`, and `rea loop --watch` commands. |

## 4. Scope & 20-Module Studio Ecosystem

### 4.1 In-Scope Capabilities

The Rust workspace manages 20 logical modules divided into native built-ins and managed external adapters:

| Slot | Module Name | Integration Type in rea-rs | Purpose in Clean-Room Workflow |
|---|---|---|---|
| 01 | rea-core | Native Rust Crate | State machine, MCP router, and native PE/ELF/Mach-O/APK triage (`goblin`/`object`). |
| 02 | Ghidra | Headless JVM Adapter (`analyzeHeadless`) | Automated batch decompilation and CFG extraction into SQLite cache. |
| 03 | GhidraMCP | Upstream MCP Proxy (stdio/HTTP) | Live interactive symbol, struct, and function inspection. |
| 04 | ida-pro-mcp | Upstream MCP Proxy (stdio/SSE) | Cross-reference (xrefs) queries and Hex-Rays decompiler bridge. |
| 05 | jadx | Managed Subprocess (`tokio::process`) | Headless DEX-to-Java AST decompilation for Android packages. |
| 06 | Apktool | Managed Subprocess (`tokio::process`) | Resource table decoding (AndroidManifest.xml, resources.arsc) and Smali disassembly. |
| 07 | Frida | `frida-gum` Rust Bindings / CLI Bridge | Dynamic runtime instrumentation, API parameter logging, and return-value tracing. |
| 08 | ILSpy | Managed Subprocess (`ilspycmd`) | Headless MSIL/.NET assembly decompilation into C# projects. |
| 09 | radare2 | `r2pipe.rs` (Async JSON Socket/Pipe) | Fast headless disassembly (`pdfj`), string searches (`izj`), and CFG JSON dumps. |
| 10 | x64dbg | Debug Server Bridge (TCP/JSON) | Windows user-mode execution trace and memory snapshot inspection. |
| 11 | ImHex | Headless CLI (`imhex --pl`) | Automated binary format parsing using ImHex Pattern Language (`.hexpat`). |
| 12 | angr | Python Worker Bridge (gRPC/JSON-RPC) | Symbolic execution and constraint solving for complex branch reachability. |
| 13 | mitmproxy | `mitmdump` HAR/JSON Stream Adapter | Capturing network serialization schemas and REST/gRPC traffic contracts. |
| 14 | dnSpy | Project Exporter / Symbol Adapter | .NET debugging metadata and PDB symbol recovery. |
| 15 | rizin | `rz-pipe` (Async JSON Pipe) | Modernized r2 alternative for structured binary analysis and ROP/gadget indexing. |
| 16 | raddebugger | Native PDB/RAD Debug Bridge | High-speed native Windows/Linux symbol and thread state inspection. |
| 17 | awesome-ai-re | Embedded Prompt & Heuristic Registry | Curated system prompts and structural analysis patterns compiled into binary. |
| 18 | awesome-re | Embedded Tool & Signature Knowledgebase | Compiler idioms, ABI calling conventions, and standard library signatures. |
| 19 | rea-workflows | Native Rust Crate | Deterministic DAG runner for multi-pass analysis and specification synthesis. |
| 20 | clean-room-loop | Native Rust Crate | Enforces the read/write barrier between Analysis and Rebuild + runs the Oracle loop. |

### 4.2 Out of Scope

- Offensive exploit generation, automated vulnerability weaponization, or DRM/license circumvention. The platform is strictly scoped to behavioral specification recovery, legacy modernization, interoperability, and clean-room software re-implementation.

## 5. Functional Requirements (FR)

### FR-1: Zero-Latency Native Triage (BINARY)

- **FR-1.1:** Upon running `rea init <target>`, the engine must hash the target (BLAKE3) and parse its binary container in-memory using `object` and `goblin` in < 50ms.
- **FR-1.2:** Automatically classify target architecture (x86_64, AArch64, JVM/Dalvik, CLR/.NET, WASM), linked libraries, security mitigations (ASLR, NX, Canary), strings, and entropy sections.
- **FR-1.3:** Run `rea doctor` to probe PATH and local sockets for modules 02–16, dynamically enabling only available MCP tools in the agent schema.

### FR-2: Bounded MCP Hub & Subprocess Multiplexer (ANALYZE)

- **FR-2.1:** Expose a single unified MCP server (`rea mcp`) over stdio so Claude Code or Cursor only needs to register one MCP server to access all 20 modules.
- **FR-2.2:** Context Window Backpressure Guard: Intercept all raw output from r2, jadx, Ghidra, and ilspycmd. Automatically truncate, paginate, or summarize outputs exceeding 64 KiB, storing the full artifact in `.rea/store.db` and returning a paginated cursor handle to the LLM.
- **FR-2.3:** Normalize cross-tool address spaces (e.g., aligning RVA/VMA offsets between radare2, Ghidra, and ImHex).

### FR-3: Clean-Room Specification Synthesis (SPEC.md)

- **FR-3.1:** Enforce a structured schema for `rebuild/SPEC.md` validated via Rust AST/Markdown parsers before transitioning to the REBUILD state. Required sections:
  - System Overview & Architecture
  - Data Types, Struct Layouts & Endianness (verified via ImHex patterns where applicable)
  - State Machines & Control Flow Contracts
  - External I/O, CLI Flags, File Formats & Network Protocols
  - Deterministic Test Vectors (Inputs -> Expected Outputs)
- **FR-3.2:** Provenance Tracking: Every requirement in SPEC.md must cite an evidence hash from the `.rea/store.db` analysis log without copying proprietary decompiled source code verbatim.

### FR-4: Isolated Clean-Room Rebuild (REBUILD)

- **FR-4.1:** Spawn the Rebuild Agent context in a restricted working directory (`./rebuild/`) where `.rea/cache/` (decompiler dumps, disassembly, smali) is strictly unmounted or denied at the MCP router level.
- **FR-4.2:** Support native build toolchains (`cargo build`, `cmake`/`make -j8`, `dotnet build`, `gradle`, `go build`) via async process runners that parse compiler diagnostics (JSON diagnostics from rustc/clang/gcc) into structured feedback.

### FR-5: Differential Behavioral Harness (ORACLE)

- **FR-5.1:** Execute both the Reference Binary and the Rebuilt Binary against the generated test corpus inside isolated sandboxes.
- **FR-5.2:** Compare across four verification tiers:
  - Tier 1 (Black-Box I/O): Exit code, stdout, stderr, and output file BLAKE3 hashes.
  - Tier 2 (Protocol/Filesystem): Created/modified files and mock network socket payloads (mitmproxy replay).
  - Tier 3 (Dynamic Trace): Syscall sequences (strace / ETW) or exported library calls (frida-gum).
  - Tier 4 (Property/Fuzz Testing): Feed mutated inputs to both binaries simultaneously to detect edge-case divergence.
- **FR-5.3:** Compute a weighted Parity Score (%) (0% to 100%) rendered live in the TUI progress bar.

### FR-6: Self-Healing Retry Loop (RETRY)

- **FR-6.1:** When the Oracle detects a mismatch, generate a Clean-Room Divergence Report containing only the failing input vector, the expected black-box output, and the actual output from the rebuild.
- **FR-6.2:** If the failure stems from an undocumented edge case in SPEC.md, automatically transition the state machine back to ANALYZE to inspect the relevant branch in the original binary, update SPEC.md, and re-trigger REBUILD.

## 6. Non-Functional Requirements (NFR)

- **NFR-1: Memory & CPU Footprint:** The rea orchestrator and TUI must consume < 35 MB of resident RAM at idle and maintain 60 FPS TUI rendering (< 16ms frame time) even while child tools (Ghidra, jadx, cargo) saturate CPU cores.
- **NFR-2: Crash Recovery & Deterministic Replay:** Every state transition and MCP tool call must be committed to SQLite WAL (`.rea/state.db`) so interrupted sessions (Esc / Ctrl+C) resume from the exact pass and tool step without repeating expensive decompilation passes.
- **NFR-3: Security Isolation:** Untrusted target binaries executed during the ORACLE phase must have network access disabled by default (loopback only) and filesystem writes restricted to a temporary tmpfs mount.

## 7. Rust Cargo Workspace Architecture

```text
rea-rs/
├── Cargo.toml                      # Workspace root (Rust 2024 edition)
├── README.md
├── crates/
│   ├── rea-cli/                    # Binary entrypoint (`rea init`, `rea loop --watch`, `rea doctor`)
│   │   └── src/main.rs
│   ├── rea-core/                   # State machine (Binary -> Analyze -> Spec -> Rebuild -> Oracle -> Retry)
│   │   └── src/
│   │       ├── pipeline.rs         # 6-stage FSM & transition guards
│   │       ├── cleanroom.rs        # Information-wall policy enforcer
│   │       ├── triage.rs           # Native ELF/PE/Mach-O/APK parser (`object`, `goblin`)
│   │       └── store.rs            # SQLite WAL artifact cache & BLAKE3 provenance
│   ├── rea-mcp/                    # Unified MCP Server + Upstream MCP Client Aggregator
│   │   └── src/
│   │       ├── router.rs           # Exposes unified toolset to Claude Code / Codex / Cursor
│   │       ├── proxy.rs            # Bridges external MCPs (GhidraMCP, ida-pro-mcp)
│   │       └── backpressure.rs     # Output chunking, pagination & token estimator
│   ├── rea-adapters/               # Async wrappers for non-MCP CLI & socket tools
│   │   └── src/
│   │       ├── r2_rizin.rs         # Async r2pipe / rz-pipe JSON client
│   │       ├── mobile.rs           # jadx, apktool, frida subprocess adapters
│   │       ├── dotnet.rs           # ilspycmd & dnSpy adapters
│   │       ├── hex_sym.rs          # ImHex pattern runner & angr worker client
│   │       └── network.rs          # mitmdump stream parser
│   ├── rea-oracle/                 # Differential Verification Engine
│   │   └── src/
│   │       ├── sandbox.rs          # Bubblewrap / Docker / JobObject isolation
│   │       ├── runner.rs           # Parallel test vector execution
│   │       └── differ.rs           # I/O, file, and trace parity calculator
│   └── rea-tui/                    # `REA.EXE STUDIO` Ratatui Terminal Interface
│       └── src/
│           ├── app.rs              # TUI state & event loop
│           ├── grid.rs             # 20-module peripheral status tiles
│           ├── agent_pane.rs       # Central Claude Code / MCP tool stream view
│           └── progress_bar.rs     # 6-stage pipeline & parity gauge renderer
├── skills/                         # Embedded via `include_str!` for agent injection
│   ├── analyze.md
│   ├── spec_writer.md
│   └── cleanroom_rebuild.md
└── templates/
    └── SPEC.md.hbs                 # Handlebars template for clean-room specifications
```

## 8. Phased Implementation Plan

### Milestone 1: Core Workspace, Native Triage & MCP Router (Week 1)

- Initialize Cargo workspace (`rea-cli`, `rea-core`, `rea-mcp`).
- Implement native binary triage (`goblin` + `object` + `capstone`) and `rea doctor` environment scanner.
- Build the `rmcp` stdio server and output backpressure paginator.

### Milestone 2: Headless Adapters & Clean-Room FSM (Week 2)

- Implement async adapters in `rea-adapters` for radare2/rizin (r2pipe), jadx, apktool, and ilspycmd.
- Build the GhidraMCP and ida-pro-mcp upstream proxy multiplexer.
- Implement the SPEC.md validator and the Clean-Room Information Wall between the Analysis and Rebuild phases.

### Milestone 3: The Oracle & Sandbox Runner (Week 3)

- Build `rea-oracle` with bubblewrap (Linux) and Docker (`bollard`) isolation.
- Implement black-box I/O diffing, parity percentage calculation, and automated divergence report generation for the RETRY loop.

### Milestone 4: REA.EXE STUDIO Ratatui Dashboard & Dynamic Tools (Week 4)

- Build the `rea-tui` dashboard replicating the exact REA.EXE STUDIO layout (20 peripheral module cards, live MCP call stream, token counter, and 6-stage progress bar).
- Add dynamic trace adapters (Frida, mitmproxy, ImHex patterns).

## 9. Acceptance Criteria & KPIs

- **Binary Startup & Triage Latency:** < 25ms cold start for `rea` CLI; < 100ms for full native static header/symbol triage on a 50MB binary.
- **Context Safety:** Zero LLM context overflow errors across 100+ consecutive tool calls via strict 64 KiB MCP response chunking.
- **Clean-Room Integrity:** 0% direct read access by the Rebuild Agent to `.rea/store.db` or raw decompiler outputs during REBUILD passes.
- **Self-Healing Parity:** Demonstrate an end-to-end automated run on a reference C or Rust CLI binary from stripped executable -> SPEC.md -> rebuilt source -> 100% Oracle test parity.
