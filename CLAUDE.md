# clawfidence

> First responder for your Markdown pipeline. Defangs prompt injection,
> strips XSS, and sanitises HTML. Your LLM reads everything… so this
> tool reads it first.

## Project spec

The full project specification, architecture, dependencies, test cases,
and TDD methodology are in `PROMPT.md`. Read it in full before starting
any work.

## Environment rules

- **pnpm** only. No npm, no yarn.
- **Never use `cd`** — zoxide overrides it. Use absolute paths or
  `git -C`.
  - **Default branch is `master`**, not main.
  - TypeScript strict mode, ESM, Node.js 20+.
  - **TDD is mandatory** — write failing tests first, then implement.
  - Test runner: vitest via `pnpm run test`.


@.fp/FP_CLAUDE.md
