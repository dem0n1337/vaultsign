```markdown
# vaultsign Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `vaultsign` repository. The codebase is primarily written in Python, with Go as the main framework. It follows strict coding conventions for file naming, imports, and exports, and uses conventional commit messages. This guide will help you contribute effectively by adhering to these patterns.

## Coding Conventions

### File Naming
- Use **camelCase** for all file names.
  - **Example:** `vaultSigner.py`, `keyManager.go`

### Import Style
- Use **relative imports** in Python modules.
  - **Example:**
    ```python
    from .utils import signData
    ```

### Export Style
- Use **named exports** (where applicable).
  - **Example (Python):**
    ```python
    def signData(...):
        ...
    __all__ = ['signData']
    ```
  - **Example (Go):**
    ```go
    func SignData(...) { ... }
    // Exported because it starts with a capital letter
    ```

### Commit Messages
- Follow **conventional commit** format.
  - **Prefixes:** `feat`, `ci`
  - **Example:** `feat: add support for new vault provider`
  - Keep commit messages concise (average 65 characters).

## Workflows

### Feature Development
**Trigger:** When implementing a new feature  
**Command:** `/feature`

1. Create a new branch for your feature.
2. Write code using camelCase file naming, relative imports, and named exports.
3. Write or update tests as needed.
4. Commit changes with a `feat:` prefix.
5. Open a pull request for review.

### Continuous Integration (CI) Updates
**Trigger:** When updating CI configuration or scripts  
**Command:** `/ci-update`

1. Edit the relevant CI files or scripts.
2. Commit changes with a `ci:` prefix.
3. Push to the repository and monitor CI results.

## Testing Patterns

- Test files use the `*.test.ts` pattern (TypeScript).
- The specific testing framework is unknown; follow existing test file structure.
- Place tests alongside or in a dedicated `tests/` directory.
- Example test file: `vaultSigner.test.ts`

## Commands

| Command      | Purpose                                   |
|--------------|-------------------------------------------|
| /feature     | Start a new feature development workflow  |
| /ci-update   | Update CI configuration/scripts           |
```
