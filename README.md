# bytelocker.el

[![CI](https://github.com/abaj8494/bytelocker.el/actions/workflows/ci.yml/badge.svg)](https://github.com/abaj8494/bytelocker.el/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/abaj8494/bytelocker.el/graph/badge.svg)](https://codecov.io/gh/abaj8494/bytelocker.el)

Encryption plugin for Emacs providing casual privacy through multiple cipher implementations.

[![demo](demo.mp4)](demo.mp4)

## Features

- Three cipher implementations: **Shift**, **XOR**, and **Caesar**
- Full buffer or region-based encryption/decryption
- Password persistence with obfuscation
- Cipher preference persistence
- Smart toggle detection (auto-detects encrypted content)

## Installation

### straight.el

```elisp
(straight-use-package
 '(bytelocker :type git :host github :repo "abaj8494/bytelocker.el"))
(require 'bytelocker)
(bytelocker-setup)
```

### straight.el + use-package

```elisp
(use-package bytelocker
  :straight (:type git :host github :repo "abaj8494/bytelocker.el")
  :config
  (bytelocker-setup))
```

### Manual

Clone this repository and add to your load path:

```elisp
(add-to-list 'load-path "/path/to/bytelocker.el")
(require 'bytelocker)
(bytelocker-setup)
```

### use-package (manual path)

```elisp
(use-package bytelocker
  :load-path "/path/to/bytelocker.el"
  :config
  (bytelocker-setup))
```

## Usage

### Commands

All commands are available via the `C-c e m` prefix:

| Key       | Command                      | Description                              |
|-----------|------------------------------|------------------------------------------|
| `C-c e m t` | `bytelocker-toggle`        | Smart toggle encryption/decryption       |
| `C-c e m e` | `bytelocker-encrypt`       | Encrypt buffer or region                 |
| `C-c e m d` | `bytelocker-decrypt`       | Decrypt buffer or region                 |
| `C-c e m c` | `bytelocker-change-cipher` | Change encryption cipher                 |
| `C-c e m p` | `bytelocker-clear-password`| Clear stored password                    |
| `C-c e m x` | `bytelocker-clear-cipher`  | Reset cipher preference                  |

### Workflow

1. Open a file in Emacs
2. Press `C-c e m t` to toggle encryption (or `C-c e m e` to explicitly encrypt)
3. Select a cipher (first time only - choice is saved)
4. Enter a password (saved for session)
5. Save the file

To decrypt:
1. Open an encrypted file
2. Press `C-c e m t` (auto-detects encryption) or `C-c e m d`
3. Password and cipher are loaded from saved preferences

### Region-based Encryption

Select a region before running any command to encrypt/decrypt only the selected text.

## Configuration

```elisp
(setq bytelocker-default-cipher 'xor)      ; Default: 'shift
(setq bytelocker-setup-keymaps nil)        ; Disable default keybindings
(setq bytelocker-data-directory "~/.config/bytelocker") ; Custom data directory
```

## Cipher Details

### Shift Cipher
Bitwise rotation cipher. Each byte is rotated left/right by an amount derived from the password.

### XOR Cipher
XOR-based encryption with rotation. Includes protection against null-input password leakage.

### Caesar Cipher
Character shifting cipher with XOR preprocessing. Provides null-byte handling protection.

## File Format

Encrypted content follows this format:
```
---BYTELOCKER-ENCRYPTED-FILE---
<base64-encoded-encrypted-data>
---END-BYTELOCKER-ENCRYPTED-FILE---
```

## Security Notice

This plugin is designed for **casual privacy**, not cryptographic security. The ciphers are educational/convenience implementations and should not be used for protecting highly sensitive data. Passwords are stored with basic obfuscation (not encryption).

## Testing

Run tests:
```bash
make test
```

Or in Emacs:
```
M-x ert RET t RET
```

## Coverage

Generate coverage report (requires [undercover.el](https://github.com/undercover-el/undercover.el)):

```bash
# Text report to stdout
make coverage

# LCOV format (for tools like genhtml, codecov)
make coverage-lcov
```

To generate an HTML coverage report:
```bash
make coverage-lcov
genhtml coverage/lcov.info -o coverage/html
open coverage/html/index.html
```

## License

MIT
