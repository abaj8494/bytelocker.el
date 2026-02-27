;;; bytelocker.el --- Encryption plugin for Emacs -*- lexical-binding: t; -*-

;; Author: Aayush Bajaj
;; Version: 1.0.1
;; Package-Requires: ((emacs "25.1"))
;; Keywords: encryption, security, privacy
;; URL: https://github.com/abaj8494/bytelocker.el

;; This file is NOT part of GNU Emacs.

;;; Commentary:

;; Bytelocker is an encryption plugin for Emacs that provides casual privacy
;; through multiple cipher implementations.  It mirrors the functionality of
;; bytelocker.nvim for Neovim.
;;
;; Features:
;; - Three cipher implementations: shift, xor, and caesar
;; - Full buffer or region-based encryption/decryption
;; - Password persistence with obfuscation
;; - Cipher preference persistence
;; - Smart toggle detection
;;
;; Usage:
;;   (require 'bytelocker)
;;   (bytelocker-setup)
;;
;; Commands are available via C-c e m prefix by default.

;;; Code:

(require 'cl-lib)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defconst bytelocker-cipher-block-size 16
  "Block size for cipher operations.")

(defconst bytelocker-magic-header "BYTELOCKR"
  "Magic header for encrypted content (9 bytes).")

(defconst bytelocker-file-header "---BYTELOCKER-ENCRYPTED-FILE---"
  "Header marker for encrypted files.")

(defconst bytelocker-file-footer "---END-BYTELOCKER-ENCRYPTED-FILE---"
  "Footer marker for encrypted files.")

(defconst bytelocker-base64-chars
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  "Base64 encoding character set.")

;;; ============================================================================
;;; Customization
;;; ============================================================================

(defgroup bytelocker nil
  "Encryption plugin for Emacs."
  :group 'tools
  :prefix "bytelocker-")

(defcustom bytelocker-default-cipher 'shift
  "Default cipher to use for encryption.
Options are `shift', `xor', or `caesar'."
  :type '(choice (const :tag "Shift Cipher" shift)
                 (const :tag "XOR Cipher" xor)
                 (const :tag "Caesar Cipher" caesar))
  :group 'bytelocker)

(defcustom bytelocker-setup-keymaps t
  "Whether to setup default keymaps on load."
  :type 'boolean
  :group 'bytelocker)

(defcustom bytelocker-data-directory
  (expand-file-name "bytelocker" user-emacs-directory)
  "Directory for storing bytelocker data files."
  :type 'directory
  :group 'bytelocker)

(defcustom bytelocker-before-encrypt-hook '(bytelocker-save-point)
  "Hook run before encrypting content.
By default, saves point position to restore after decryption."
  :type 'hook
  :group 'bytelocker)

(defcustom bytelocker-after-encrypt-hook nil
  "Hook run after encrypting content."
  :type 'hook
  :group 'bytelocker)

(defcustom bytelocker-before-decrypt-hook nil
  "Hook run before decrypting content."
  :type 'hook
  :group 'bytelocker)

(defcustom bytelocker-after-decrypt-hook '(bytelocker-restore-point)
  "Hook run after decrypting content.
By default, restores point to position saved before encryption."
  :type 'hook
  :group 'bytelocker)

;;; ============================================================================
;;; Internal State
;;; ============================================================================

(defvar bytelocker--stored-password nil
  "In-memory cached password.")

(defvar bytelocker--current-cipher nil
  "Currently selected cipher.")

(defvar-local bytelocker--saved-point nil
  "Buffer-local saved point position for restoration after decryption.")

;;; ============================================================================
;;; File Paths
;;; ============================================================================

(defun bytelocker--password-file ()
  "Return the path to the password storage file."
  (expand-file-name "bytelocker_session.dat" bytelocker-data-directory))

(defun bytelocker--cipher-file ()
  "Return the path to the cipher preference file."
  (expand-file-name "bytelocker_cipher.dat" bytelocker-data-directory))

(defun bytelocker--ensure-data-directory ()
  "Ensure the data directory exists."
  (unless (file-exists-p bytelocker-data-directory)
    (make-directory bytelocker-data-directory t)))

;;; ============================================================================
;;; Bit Operations (8-bit)
;;; ============================================================================

(defun bytelocker--rol8 (byte amount)
  "Rotate BYTE left by AMOUNT bits (8-bit)."
  (let ((byte (logand byte #xff))
        (amount (mod amount 8)))
    (logand (logior (ash byte amount)
                    (ash byte (- amount 8)))
            #xff)))

(defun bytelocker--ror8 (byte amount)
  "Rotate BYTE right by AMOUNT bits (8-bit)."
  (let ((byte (logand byte #xff))
        (amount (mod amount 8)))
    (logand (logior (ash byte (- amount))
                    (ash byte (- 8 amount)))
            #xff)))

;;; ============================================================================
;;; Base64 Encoding/Decoding
;;; ============================================================================

(defun bytelocker--base64-encode (bytes)
  "Encode BYTES (list of integers 0-255) to Base64 string."
  (let* ((len (length bytes))
         (result '())
         (i 0))
    (while (< i len)
      (let* ((b1 (nth i bytes))
             (b2 (if (< (1+ i) len) (nth (1+ i) bytes) 0))
             (b3 (if (< (+ i 2) len) (nth (+ i 2) bytes) 0))
             (n (logior (ash b1 16) (ash b2 8) b3)))
        (push (aref bytelocker-base64-chars (logand (ash n -18) #x3f)) result)
        (push (aref bytelocker-base64-chars (logand (ash n -12) #x3f)) result)
        (if (< (1+ i) len)
            (push (aref bytelocker-base64-chars (logand (ash n -6) #x3f)) result)
          (push ?= result))
        (if (< (+ i 2) len)
            (push (aref bytelocker-base64-chars (logand n #x3f)) result)
          (push ?= result))
        (setq i (+ i 3))))
    (apply #'string (nreverse result))))

(defun bytelocker--base64-decode (str)
  "Decode Base64 STR to list of bytes."
  (let ((result '())
        (len (length str))
        (i 0)
        (decode-table (make-hash-table :test 'eq)))
    ;; Build decode table
    (dotimes (j 64)
      (puthash (aref bytelocker-base64-chars j) j decode-table))
    ;; Decode
    (while (< i len)
      (let* ((c1 (gethash (aref str i) decode-table 0))
             (c2 (gethash (aref str (1+ i)) decode-table 0))
             (c3 (if (and (< (+ i 2) len) (not (= (aref str (+ i 2)) ?=)))
                     (gethash (aref str (+ i 2)) decode-table 0)
                   nil))
             (c4 (if (and (< (+ i 3) len) (not (= (aref str (+ i 3)) ?=)))
                     (gethash (aref str (+ i 3)) decode-table 0)
                   nil))
             (n (logior (ash c1 18)
                        (ash c2 12)
                        (if c3 (ash c3 6) 0)
                        (or c4 0))))
        (push (logand (ash n -16) #xff) result)
        (when c3
          (push (logand (ash n -8) #xff) result))
        (when c4
          (push (logand n #xff) result))
        (setq i (+ i 4))))
    (nreverse result)))

;;; ============================================================================
;;; Password Management
;;; ============================================================================

(defun bytelocker--obfuscate-byte (byte)
  "Obfuscate a single BYTE using simple shift."
  (mod (+ byte 42) 256))

(defun bytelocker--deobfuscate-byte (byte)
  "Deobfuscate a single BYTE using simple shift."
  (mod (+ (- byte 42) 256) 256))

(defun bytelocker--save-password (password)
  "Save PASSWORD to disk with obfuscation."
  (bytelocker--ensure-data-directory)
  (let ((bytes (mapcar #'bytelocker--obfuscate-byte
                       (string-to-list password))))
    (with-temp-file (bytelocker--password-file)
      (set-buffer-multibyte nil)
      (insert (apply #'unibyte-string bytes)))))

(defun bytelocker--load-password ()
  "Load password from disk if it exists."
  (let ((file (bytelocker--password-file)))
    (when (file-exists-p file)
      (with-temp-buffer
        (set-buffer-multibyte nil)
        (insert-file-contents-literally file)
        (let ((bytes (mapcar #'bytelocker--deobfuscate-byte
                             (string-to-list (buffer-string)))))
          (apply #'string bytes))))))

(defun bytelocker--get-password ()
  "Get password from memory, disk, or prompt user."
  (or bytelocker--stored-password
      (let ((loaded (bytelocker--load-password)))
        (when loaded
          (setq bytelocker--stored-password loaded)
          (message "Bytelocker: Password loaded from disk")
          loaded))
      (let ((password (read-passwd "Bytelocker password: ")))
        (if (string-empty-p password)
            (progn
              (message "Bytelocker: Password cannot be empty")
              nil)
          (setq bytelocker--stored-password password)
          (bytelocker--save-password password)
          (message "Bytelocker: Password saved")
          password))))

(defun bytelocker-clear-password ()
  "Clear stored password from memory and disk."
  (interactive)
  (setq bytelocker--stored-password nil)
  (let ((file (bytelocker--password-file)))
    (when (file-exists-p file)
      (delete-file file)))
  (message "Bytelocker: Password cleared"))

;;; ============================================================================
;;; Cipher Management
;;; ============================================================================

(defun bytelocker--save-cipher (cipher)
  "Save CIPHER preference to disk."
  (bytelocker--ensure-data-directory)
  (with-temp-file (bytelocker--cipher-file)
    (insert (symbol-name cipher))))

(defun bytelocker--load-cipher ()
  "Load cipher preference from disk if it exists."
  (let ((file (bytelocker--cipher-file)))
    (when (file-exists-p file)
      (with-temp-buffer
        (insert-file-contents file)
        (intern (string-trim (buffer-string)))))))

(defun bytelocker--get-cipher ()
  "Get current cipher, prompting if not set."
  (or bytelocker--current-cipher
      (let ((loaded (bytelocker--load-cipher)))
        (when loaded
          (setq bytelocker--current-cipher loaded)
          (message "Bytelocker: Cipher '%s' loaded from disk" loaded)
          loaded))
      (bytelocker-change-cipher)))

(defun bytelocker-change-cipher ()
  "Interactively change the encryption cipher."
  (interactive)
  (let* ((choices '(("Shift Cipher - Bitwise rotation cipher" . shift)
                    ("XOR Cipher - XOR-based encryption" . xor)
                    ("Caesar Cipher - Character shifting cipher" . caesar)))
         (choice (completing-read "Select cipher: " choices nil t))
         (cipher (cdr (assoc choice choices))))
    (setq bytelocker--current-cipher cipher)
    (bytelocker--save-cipher cipher)
    (message "Bytelocker: Cipher set to '%s'" cipher)
    cipher))

(defun bytelocker-clear-cipher ()
  "Reset cipher choice to default and clear from disk."
  (interactive)
  (setq bytelocker--current-cipher nil)
  (let ((file (bytelocker--cipher-file)))
    (when (file-exists-p file)
      (delete-file file)))
  (message "Bytelocker: Cipher preference cleared"))

;;; ============================================================================
;;; Password Preparation
;;; ============================================================================

(defun bytelocker--prepare-password (password)
  "Prepare PASSWORD into a 16-byte key by cycling characters."
  (let* ((pwd-bytes (string-to-list password))
         (pwd-len (length pwd-bytes))
         (key (make-list bytelocker-cipher-block-size 0)))
    (dotimes (i bytelocker-cipher-block-size)
      (setf (nth i key) (nth (mod i pwd-len) pwd-bytes)))
    key))

;;; ============================================================================
;;; Cipher Implementations
;;; ============================================================================

;; --- Shift Cipher ---

(defun bytelocker--shift-encrypt-block (block key)
  "Encrypt BLOCK using shift cipher with KEY."
  (cl-mapcar (lambda (byte key-byte)
               (bytelocker--rol8 byte (mod key-byte 8)))
             block key))

(defun bytelocker--shift-decrypt-block (block key)
  "Decrypt BLOCK using shift cipher with KEY."
  (cl-mapcar (lambda (byte key-byte)
               (bytelocker--ror8 byte (mod key-byte 8)))
             block key))

;; --- XOR Cipher ---

(defun bytelocker--xor-encrypt-block (block key)
  "Encrypt BLOCK using XOR cipher with KEY."
  (cl-mapcar (lambda (byte key-byte)
               (let* ((safe-byte (mod (1+ byte) 256))
                      (rotation (1+ (mod key-byte 7)))
                      (rotated (bytelocker--rol8 safe-byte rotation)))
                 (logxor rotated key-byte)))
             block key))

(defun bytelocker--xor-decrypt-block (block key)
  "Decrypt BLOCK using XOR cipher with KEY."
  (cl-mapcar (lambda (byte key-byte)
               (let* ((rotated (logxor byte key-byte))
                      (rotation (1+ (mod key-byte 7)))
                      (safe-byte (bytelocker--ror8 rotated rotation)))
                 (mod (+ (1- safe-byte) 256) 256)))
             block key))

;; --- Caesar Cipher ---

(defun bytelocker--caesar-encrypt-block (block key)
  "Encrypt BLOCK using Caesar cipher with KEY."
  (cl-mapcar (lambda (byte key-byte)
               (let* ((intermediate (logxor byte key-byte))
                      (shift (mod key-byte 128)))
                 (mod (+ intermediate shift 1) 256)))
             block key))

(defun bytelocker--caesar-decrypt-block (block key)
  "Decrypt BLOCK using Caesar cipher with KEY."
  (cl-mapcar (lambda (byte key-byte)
               (let* ((shift (mod key-byte 128))
                      (intermediate (mod (+ (- byte shift 1) 256) 256)))
                 (logxor intermediate key-byte)))
             block key))

;; --- Cipher Dispatcher ---

(defun bytelocker--encrypt-block (block key cipher)
  "Encrypt BLOCK with KEY using CIPHER."
  (pcase cipher
    ('shift (bytelocker--shift-encrypt-block block key))
    ('xor (bytelocker--xor-encrypt-block block key))
    ('caesar (bytelocker--caesar-encrypt-block block key))
    (_ (bytelocker--shift-encrypt-block block key))))

(defun bytelocker--decrypt-block (block key cipher)
  "Decrypt BLOCK with KEY using CIPHER."
  (pcase cipher
    ('shift (bytelocker--shift-decrypt-block block key))
    ('xor (bytelocker--xor-decrypt-block block key))
    ('caesar (bytelocker--caesar-decrypt-block block key))
    (_ (bytelocker--shift-decrypt-block block key))))

;;; ============================================================================
;;; Encryption/Decryption Core
;;; ============================================================================

(defun bytelocker--pad-to-block-size (bytes)
  "Pad BYTES list to multiple of block size with zeros."
  (let* ((len (length bytes))
         (remainder (mod len bytelocker-cipher-block-size)))
    (if (zerop remainder)
        bytes
      (append bytes (make-list (- bytelocker-cipher-block-size remainder) 0)))))

(defun bytelocker--int-to-bytes (n)
  "Convert integer N to 4-byte big-endian list."
  (list (logand (ash n -24) #xff)
        (logand (ash n -16) #xff)
        (logand (ash n -8) #xff)
        (logand n #xff)))

(defun bytelocker--bytes-to-int (bytes)
  "Convert 4-byte big-endian BYTES list to integer."
  (logior (ash (nth 0 bytes) 24)
          (ash (nth 1 bytes) 16)
          (ash (nth 2 bytes) 8)
          (nth 3 bytes)))

(defun bytelocker--encrypt-bytes (bytes password cipher)
  "Encrypt BYTES with PASSWORD using CIPHER."
  (let* ((key (bytelocker--prepare-password password))
         (original-length (length bytes))
         (length-bytes (bytelocker--int-to-bytes original-length))
         (magic-bytes (string-to-list bytelocker-magic-header))
         (content-bytes (append magic-bytes length-bytes bytes))
         (padded (bytelocker--pad-to-block-size content-bytes))
         (result '())
         (i 0))
    (while (< i (length padded))
      (let ((block (cl-subseq padded i (+ i bytelocker-cipher-block-size))))
        (setq result (append result (bytelocker--encrypt-block block key cipher)))
        (setq i (+ i bytelocker-cipher-block-size))))
    result))

(defun bytelocker--decrypt-bytes (bytes password cipher)
  "Decrypt BYTES with PASSWORD using CIPHER.
Returns decrypted bytes or nil on failure."
  (let* ((key (bytelocker--prepare-password password))
         (decrypted '())
         (i 0))
    ;; Decrypt all blocks
    (while (< i (length bytes))
      (let* ((end (min (+ i bytelocker-cipher-block-size) (length bytes)))
             (block (cl-subseq bytes i end)))
        ;; Pad incomplete block
        (when (< (length block) bytelocker-cipher-block-size)
          (setq block (append block (make-list (- bytelocker-cipher-block-size (length block)) 0))))
        (setq decrypted (append decrypted (bytelocker--decrypt-block block key cipher)))
        (setq i (+ i bytelocker-cipher-block-size))))
    ;; Validate magic header
    (let ((magic-len (length bytelocker-magic-header)))
      (when (>= (length decrypted) (+ magic-len 4))
        (let ((header (apply #'string (cl-subseq decrypted 0 magic-len))))
          (if (string= header bytelocker-magic-header)
              (let* ((length-bytes (cl-subseq decrypted magic-len (+ magic-len 4)))
                     (original-length (bytelocker--bytes-to-int length-bytes))
                     (content-start (+ magic-len 4)))
                (when (<= (+ content-start original-length) (length decrypted))
                  (if (zerop original-length)
                      :empty  ; Sentinel for empty content
                    (cl-subseq decrypted content-start (+ content-start original-length)))))
            nil))))))

;;; ============================================================================
;;; File Format Functions
;;; ============================================================================

(defun bytelocker--string-to-bytes (str)
  "Convert STR to list of UTF-8 bytes."
  (append (encode-coding-string str 'utf-8) nil))

(defun bytelocker--bytes-to-string (bytes)
  "Convert list of UTF-8 BYTES to string."
  (decode-coding-string (apply #'unibyte-string bytes) 'utf-8))

(defun bytelocker--encrypt-for-file (content password cipher)
  "Encrypt CONTENT string for file storage with PASSWORD and CIPHER."
  (let* ((bytes (bytelocker--string-to-bytes content))
         (encrypted (bytelocker--encrypt-bytes bytes password cipher))
         (base64 (bytelocker--base64-encode encrypted)))
    (concat bytelocker-file-header "\n" base64 "\n" bytelocker-file-footer)))

(defun bytelocker--decrypt-from-file (content password cipher)
  "Decrypt file-formatted CONTENT with PASSWORD and CIPHER.
Returns decrypted string or nil on failure."
  (when (bytelocker--is-file-encrypted content)
    (let* ((lines (split-string content "\n"))
           (base64-content (string-trim (nth 1 lines)))
           (encrypted-bytes (bytelocker--base64-decode base64-content))
           (decrypted-bytes (bytelocker--decrypt-bytes encrypted-bytes password cipher)))
      (cond
       ;; nil means decryption failed (wrong password/cipher)
       ((null decrypted-bytes) nil)
       ;; :empty sentinel means original content was empty
       ((eq decrypted-bytes :empty) "")
       (t (bytelocker--bytes-to-string decrypted-bytes))))))

;;; ============================================================================
;;; Format Detection
;;; ============================================================================

(defun bytelocker--is-file-encrypted (content)
  "Check if CONTENT is in encrypted file format."
  (string-prefix-p bytelocker-file-header content))

(defun bytelocker--is-text-encrypted (content)
  "Check if CONTENT has magic header (for internal use)."
  (and (>= (length content) (length bytelocker-magic-header))
       (string= (substring content 0 (length bytelocker-magic-header))
                bytelocker-magic-header)))

(defun bytelocker--is-encrypted (content)
  "Check if CONTENT is encrypted in any format."
  (or (bytelocker--is-file-encrypted content)
      (bytelocker--is-text-encrypted content)))

;;; ============================================================================
;;; Buffer Operations
;;; ============================================================================

(defun bytelocker--get-content ()
  "Get content to encrypt/decrypt (region or buffer)."
  (if (use-region-p)
      (buffer-substring-no-properties (region-beginning) (region-end))
    (buffer-substring-no-properties (point-min) (point-max))))

(defun bytelocker--replace-content (new-content)
  "Replace current content (region or buffer) with NEW-CONTENT."
  (if (use-region-p)
      (let ((beg (region-beginning))
            (end (region-end)))
        (delete-region beg end)
        (goto-char beg)
        (insert new-content))
    (erase-buffer)
    (insert new-content))
  (set-buffer-modified-p t))

(defun bytelocker--buffer-has-read-only-p ()
  "Return t if the current buffer contains any read-only text regions."
  (let ((pos (point-min))
        (found nil))
    (while (and (not found) (< pos (point-max)))
      (if (get-text-property pos 'read-only)
          (setq found t)
        (let ((next (next-single-property-change pos 'read-only)))
          (setq pos (or next (point-max))))))
    found))

(defun bytelocker--get-writable-regions ()
  "Return list of (BEG . END) pairs for non-read-only regions.
Skips empty regions where BEG = END."
  (let ((pos (point-min))
        (regions '()))
    (while (< pos (point-max))
      (if (get-text-property pos 'read-only)
          ;; Skip read-only region
          (setq pos (or (next-single-property-change pos 'read-only)
                        (point-max)))
        ;; Writable region
        (let ((end (or (next-single-property-change pos 'read-only)
                       (point-max))))
          (when (< pos end)
            (push (cons pos end) regions))
          (setq pos end))))
    (nreverse regions)))

(defun bytelocker--encrypt-writable-regions (password cipher)
  "Encrypt each writable region with PASSWORD and CIPHER.
Processes regions end-to-start so positions remain valid.
Skips already-encrypted and whitespace-only regions."
  (run-hooks 'bytelocker-before-encrypt-hook)
  (let ((regions (reverse (bytelocker--get-writable-regions)))
        (encrypted-count 0))
    (dolist (region regions)
      (let* ((beg (car region))
             (end (cdr region))
             (content (buffer-substring-no-properties beg end)))
        (unless (or (bytelocker--is-encrypted content)
                    (string-match-p "\\`[ \t\n\r]*\\'" content))
          (let ((encrypted (bytelocker--encrypt-for-file content password cipher)))
            (save-excursion
              (let ((inhibit-read-only t))
                (delete-region beg end)
                (goto-char beg)
                (insert encrypted)))
            (setq encrypted-count (1+ encrypted-count))))))
    (when (> encrypted-count 0)
      (set-buffer-modified-p t)
      (message "Bytelocker: Encrypted %d region(s) with '%s' cipher"
               encrypted-count cipher))
    (run-hooks 'bytelocker-after-encrypt-hook)))

(defun bytelocker--encrypted-block-at-point ()
  "Return (BEG . END) of encrypted block surrounding point, or nil."
  (save-excursion
    (let ((here (point))
          header-beg footer-end)
      ;; Search backward for header from end of current line
      (goto-char (line-end-position))
      (when (search-backward bytelocker-file-header nil t)
        (setq header-beg (point))
        ;; Search forward for footer from header
        (goto-char header-beg)
        (when (search-forward bytelocker-file-footer nil t)
          (setq footer-end (point))
          ;; Validate point falls within the block
          (when (and (<= header-beg here) (<= here footer-end))
            (cons header-beg footer-end)))))))

(defun bytelocker--decrypt-block-at-point (bounds)
  "Decrypt the encrypted block at BOUNDS (BEG . END).
BOUNDS is a cons cell as returned by `bytelocker--encrypted-block-at-point'."
  (let* ((beg (car bounds))
         (end (cdr bounds))
         (content (buffer-substring-no-properties beg end))
         (password (bytelocker--get-password))
         (cipher (bytelocker--get-cipher)))
    (if (not password)
        (message "Bytelocker: Decryption cancelled - no password")
      (run-hooks 'bytelocker-before-decrypt-hook)
      (let ((decrypted (bytelocker--decrypt-from-file content password cipher)))
        (if decrypted
            (progn
              (save-excursion
                (delete-region beg end)
                (goto-char beg)
                (insert decrypted))
              (set-buffer-modified-p t)
              (message "Bytelocker: Block decrypted successfully")
              (run-hooks 'bytelocker-after-decrypt-hook))
          (message "Bytelocker: Decryption failed - wrong password or cipher?"))))))

;;; ============================================================================
;;; Hook Helpers
;;; ============================================================================

(defun bytelocker-save-point ()
  "Save current point position for later restoration.
Called before encryption to remember cursor position."
  (setq bytelocker--saved-point (point)))

(defun bytelocker-restore-point ()
  "Restore point to previously saved position.
Called after decryption to return cursor to original location."
  (when bytelocker--saved-point
    (goto-char (min bytelocker--saved-point (point-max)))
    (setq bytelocker--saved-point nil)))

(defun bytelocker-push-global-mark ()
  "Push current position to the global mark ring.
This allows jumping back with \\[pop-global-mark] after encryption/decryption.
Does nothing in batch mode."
  (unless noninteractive
    (let ((marker (copy-marker (point-marker))))
      (setq global-mark-ring (cons marker global-mark-ring))
      ;; Limit global mark ring size
      (when (> (length global-mark-ring) global-mark-ring-max)
        (move-marker (car (nthcdr global-mark-ring-max global-mark-ring)) nil)
        (setcdr (nthcdr (1- global-mark-ring-max) global-mark-ring) nil)))))

;;; ============================================================================
;;; Public Commands
;;; ============================================================================

;;;###autoload
(defun bytelocker-encrypt ()
  "Encrypt current buffer or region.
When the buffer contains read-only text and no region is active,
offers to encrypt around read-only regions individually."
  (interactive)
  (if (and (not (use-region-p))
           (bytelocker--buffer-has-read-only-p))
      ;; Buffer has read-only text — offer to encrypt around it
      (when (y-or-n-p "Encrypt around read-only text? ")
        (let ((password (bytelocker--get-password))
              (cipher (bytelocker--get-cipher)))
          (when password
            (bytelocker--encrypt-writable-regions password cipher))))
    ;; Original behavior
    (let* ((content (bytelocker--get-content))
           (password (bytelocker--get-password))
           (cipher (bytelocker--get-cipher)))
      (if (not password)
          (message "Bytelocker: Encryption cancelled - no password")
        (if (bytelocker--is-encrypted content)
            (message "Bytelocker: Content is already encrypted")
          (run-hooks 'bytelocker-before-encrypt-hook)
          (let ((encrypted (bytelocker--encrypt-for-file content password cipher)))
            (bytelocker--replace-content encrypted)
            (message "Bytelocker: Content encrypted with '%s' cipher" cipher)
            (run-hooks 'bytelocker-after-encrypt-hook)))))))

;;;###autoload
(defun bytelocker-decrypt ()
  "Decrypt current buffer, region, or encrypted block at point."
  (interactive)
  (let ((block (and (not (use-region-p))
                    (bytelocker--encrypted-block-at-point))))
    (if block
        (bytelocker--decrypt-block-at-point block)
      ;; Original behavior
      (let* ((content (bytelocker--get-content))
             (password (bytelocker--get-password))
             (cipher (bytelocker--get-cipher)))
        (if (not password)
            (message "Bytelocker: Decryption cancelled - no password")
          (if (not (bytelocker--is-encrypted content))
              (message "Bytelocker: Content is not encrypted")
            (run-hooks 'bytelocker-before-decrypt-hook)
            (let ((decrypted (bytelocker--decrypt-from-file content password cipher)))
              (if decrypted
                  (progn
                    (bytelocker--replace-content decrypted)
                    (message "Bytelocker: Content decrypted successfully")
                    (run-hooks 'bytelocker-after-decrypt-hook))
                (message "Bytelocker: Decryption failed - wrong password or cipher?")))))))))

;;;###autoload
(defun bytelocker-toggle ()
  "Toggle encryption/decryption based on current content state.
If point is inside an encrypted block, decrypts just that block."
  (interactive)
  (let ((block (and (not (use-region-p))
                    (bytelocker--encrypted-block-at-point))))
    (if block
        (bytelocker--decrypt-block-at-point block)
      (let ((content (bytelocker--get-content)))
        (if (bytelocker--is-encrypted content)
            (bytelocker-decrypt)
          (bytelocker-encrypt))))))

;;; ============================================================================
;;; Keymap Setup
;;; ============================================================================

(defvar bytelocker-command-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "t") #'bytelocker-toggle)
    (define-key map (kbd "e") #'bytelocker-encrypt)
    (define-key map (kbd "d") #'bytelocker-decrypt)
    (define-key map (kbd "c") #'bytelocker-change-cipher)
    (define-key map (kbd "p") #'bytelocker-clear-password)
    (define-key map (kbd "x") #'bytelocker-clear-cipher)
    map)
  "Command map for Bytelocker.
\\{bytelocker-command-map}")

;;;###autoload
(defun bytelocker-setup ()
  "Setup bytelocker with default keybindings."
  (interactive)
  (when bytelocker-setup-keymaps
    (global-set-key (kbd "C-c e m") bytelocker-command-map))
  (message "Bytelocker: Initialized"))

;;; ============================================================================
;;; Minor Mode (Optional)
;;; ============================================================================

;;;###autoload
(define-minor-mode bytelocker-mode
  "Minor mode for Bytelocker encryption commands."
  :lighter " BL"
  :keymap (let ((map (make-sparse-keymap)))
            (define-key map (kbd "C-c e m") bytelocker-command-map)
            map)
  :group 'bytelocker)

;;;###autoload
(define-globalized-minor-mode global-bytelocker-mode
  bytelocker-mode
  (lambda () (bytelocker-mode 1))
  :group 'bytelocker)

(provide 'bytelocker)

;;; bytelocker.el ends here
