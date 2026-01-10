;;; bytelocker-test.el --- Tests for bytelocker.el -*- lexical-binding: t; -*-

;; This file contains tests for bytelocker.el using ERT (Emacs Lisp Regression Testing)

;;; Commentary:

;; Run tests with: emacs -batch -l ert -l bytelocker.el -l bytelocker-test.el -f ert-run-tests-batch-and-exit
;; Or interactively: M-x ert RET t RET

;;; Code:

(require 'ert)
(require 'bytelocker)

;;; ============================================================================
;;; Bit Operations Tests
;;; ============================================================================

(ert-deftest bytelocker-test-rol8-basic ()
  "Test basic ROL8 rotation."
  (should (= (bytelocker--rol8 #b10000000 1) #b00000001))
  (should (= (bytelocker--rol8 #b00000001 1) #b00000010))
  (should (= (bytelocker--rol8 #b11110000 4) #b00001111)))

(ert-deftest bytelocker-test-ror8-basic ()
  "Test basic ROR8 rotation."
  (should (= (bytelocker--ror8 #b00000001 1) #b10000000))
  (should (= (bytelocker--ror8 #b00000010 1) #b00000001))
  (should (= (bytelocker--ror8 #b00001111 4) #b11110000)))

(ert-deftest bytelocker-test-rol8-ror8-inverse ()
  "Test that ROL8 and ROR8 are inverses."
  (dolist (byte '(0 1 127 128 255))
    (dolist (amount '(0 1 3 7 8))
      (should (= byte (bytelocker--ror8 (bytelocker--rol8 byte amount) amount)))
      (should (= byte (bytelocker--rol8 (bytelocker--ror8 byte amount) amount))))))

(ert-deftest bytelocker-test-rol8-full-rotation ()
  "Test that rotating by 8 returns original value."
  (dolist (byte '(0 42 128 255))
    (should (= byte (bytelocker--rol8 byte 8)))
    (should (= byte (bytelocker--ror8 byte 8)))))

(ert-deftest bytelocker-test-rol8-modulo ()
  "Test that rotation amount is modulo 8."
  (should (= (bytelocker--rol8 #b10000000 9) (bytelocker--rol8 #b10000000 1)))
  (should (= (bytelocker--rol8 #b10000000 16) #b10000000)))

;;; ============================================================================
;;; Base64 Tests
;;; ============================================================================

(ert-deftest bytelocker-test-base64-encode-basic ()
  "Test basic Base64 encoding."
  (should (string= (bytelocker--base64-encode '(77 97 110)) "TWFu"))
  (should (string= (bytelocker--base64-encode '(77 97)) "TWE="))
  (should (string= (bytelocker--base64-encode '(77)) "TQ==")))

(ert-deftest bytelocker-test-base64-decode-basic ()
  "Test basic Base64 decoding."
  (should (equal (bytelocker--base64-decode "TWFu") '(77 97 110)))
  (should (equal (bytelocker--base64-decode "TWE=") '(77 97)))
  (should (equal (bytelocker--base64-decode "TQ==") '(77))))

(ert-deftest bytelocker-test-base64-roundtrip ()
  "Test Base64 encode/decode roundtrip."
  (let ((test-cases '((72 101 108 108 111)  ; "Hello"
                      (0 1 2 3 4 5)
                      (255 254 253)
                      (0)
                      (255))))
    (dolist (bytes test-cases)
      (should (equal bytes (bytelocker--base64-decode (bytelocker--base64-encode bytes)))))))

(ert-deftest bytelocker-test-base64-all-bytes ()
  "Test Base64 handles all byte values."
  (let ((all-bytes (number-sequence 0 255)))
    (should (equal all-bytes
                   (bytelocker--base64-decode (bytelocker--base64-encode all-bytes))))))

;;; ============================================================================
;;; Password Obfuscation Tests
;;; ============================================================================

(ert-deftest bytelocker-test-obfuscate-roundtrip ()
  "Test obfuscation/deobfuscation roundtrip."
  (dolist (byte (number-sequence 0 255))
    (should (= byte (bytelocker--deobfuscate-byte (bytelocker--obfuscate-byte byte))))))

(ert-deftest bytelocker-test-obfuscate-different ()
  "Test that obfuscation changes values."
  (dolist (byte '(0 42 128 255))
    (should-not (= byte (bytelocker--obfuscate-byte byte)))))

;;; ============================================================================
;;; Password Preparation Tests
;;; ============================================================================

(ert-deftest bytelocker-test-prepare-password-length ()
  "Test password preparation produces correct length."
  (should (= (length (bytelocker--prepare-password "test")) bytelocker-cipher-block-size))
  (should (= (length (bytelocker--prepare-password "a")) bytelocker-cipher-block-size))
  (should (= (length (bytelocker--prepare-password "verylongpassword12345")) bytelocker-cipher-block-size)))

(ert-deftest bytelocker-test-prepare-password-cycling ()
  "Test password cycles correctly."
  (let ((key (bytelocker--prepare-password "ab")))
    (should (= (nth 0 key) ?a))
    (should (= (nth 1 key) ?b))
    (should (= (nth 2 key) ?a))
    (should (= (nth 3 key) ?b))))

(ert-deftest bytelocker-test-prepare-password-deterministic ()
  "Test password preparation is deterministic."
  (should (equal (bytelocker--prepare-password "test")
                 (bytelocker--prepare-password "test"))))

;;; ============================================================================
;;; Cipher Block Tests
;;; ============================================================================

(ert-deftest bytelocker-test-shift-cipher-roundtrip ()
  "Test shift cipher encryption/decryption roundtrip."
  (let* ((key (bytelocker--prepare-password "testkey"))
         (block (make-list bytelocker-cipher-block-size 42)))
    (should (equal block
                   (bytelocker--shift-decrypt-block
                    (bytelocker--shift-encrypt-block block key) key)))))

(ert-deftest bytelocker-test-xor-cipher-roundtrip ()
  "Test XOR cipher encryption/decryption roundtrip."
  (let* ((key (bytelocker--prepare-password "testkey"))
         (block (make-list bytelocker-cipher-block-size 42)))
    (should (equal block
                   (bytelocker--xor-decrypt-block
                    (bytelocker--xor-encrypt-block block key) key)))))

(ert-deftest bytelocker-test-caesar-cipher-roundtrip ()
  "Test Caesar cipher encryption/decryption roundtrip."
  (let* ((key (bytelocker--prepare-password "testkey"))
         (block (make-list bytelocker-cipher-block-size 42)))
    (should (equal block
                   (bytelocker--caesar-decrypt-block
                    (bytelocker--caesar-encrypt-block block key) key)))))

(ert-deftest bytelocker-test-ciphers-change-data ()
  "Test that encryption actually changes data."
  (let* ((key (bytelocker--prepare-password "testkey"))
         (block (make-list bytelocker-cipher-block-size 42)))
    (should-not (equal block (bytelocker--shift-encrypt-block block key)))
    (should-not (equal block (bytelocker--xor-encrypt-block block key)))
    (should-not (equal block (bytelocker--caesar-encrypt-block block key)))))

(ert-deftest bytelocker-test-all-ciphers-all-bytes ()
  "Test all ciphers handle all byte values."
  (let ((key (bytelocker--prepare-password "testkey")))
    (dotimes (i 256)
      (let ((block (make-list bytelocker-cipher-block-size i)))
        ;; Shift
        (should (equal block
                       (bytelocker--shift-decrypt-block
                        (bytelocker--shift-encrypt-block block key) key)))
        ;; XOR
        (should (equal block
                       (bytelocker--xor-decrypt-block
                        (bytelocker--xor-encrypt-block block key) key)))
        ;; Caesar
        (should (equal block
                       (bytelocker--caesar-decrypt-block
                        (bytelocker--caesar-encrypt-block block key) key)))))))

;;; ============================================================================
;;; Length Encoding Tests
;;; ============================================================================

(ert-deftest bytelocker-test-int-bytes-roundtrip ()
  "Test integer to bytes conversion roundtrip."
  (dolist (n '(0 1 255 256 65535 16777215 #xFFFFFFFF))
    (let ((limited (logand n #xFFFFFFFF)))  ; Ensure 32-bit
      (should (= limited (bytelocker--bytes-to-int (bytelocker--int-to-bytes limited)))))))

(ert-deftest bytelocker-test-int-to-bytes-format ()
  "Test integer to bytes produces big-endian format."
  (should (equal (bytelocker--int-to-bytes #x12345678) '(#x12 #x34 #x56 #x78)))
  (should (equal (bytelocker--int-to-bytes 256) '(0 0 1 0))))

;;; ============================================================================
;;; Encryption/Decryption Roundtrip Tests
;;; ============================================================================

(ert-deftest bytelocker-test-encrypt-decrypt-roundtrip-shift ()
  "Test full encryption/decryption roundtrip with shift cipher."
  (let ((content "Hello, World!")
        (password "testpassword"))
    (should (string= content
                     (bytelocker--decrypt-from-file
                      (bytelocker--encrypt-for-file content password 'shift)
                      password 'shift)))))

(ert-deftest bytelocker-test-encrypt-decrypt-roundtrip-xor ()
  "Test full encryption/decryption roundtrip with XOR cipher."
  (let ((content "Hello, World!")
        (password "testpassword"))
    (should (string= content
                     (bytelocker--decrypt-from-file
                      (bytelocker--encrypt-for-file content password 'xor)
                      password 'xor)))))

(ert-deftest bytelocker-test-encrypt-decrypt-roundtrip-caesar ()
  "Test full encryption/decryption roundtrip with Caesar cipher."
  (let ((content "Hello, World!")
        (password "testpassword"))
    (should (string= content
                     (bytelocker--decrypt-from-file
                      (bytelocker--encrypt-for-file content password 'caesar)
                      password 'caesar)))))

(ert-deftest bytelocker-test-encrypt-decrypt-multiline ()
  "Test encryption/decryption with multiline content."
  (let ((content "Line 1\nLine 2\nLine 3\n")
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

(ert-deftest bytelocker-test-encrypt-decrypt-unicode ()
  "Test encryption/decryption with Unicode content."
  (let ((content "Hello, \u4e16\u754c! \u00e9\u00e8\u00ea \u2764")
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

(ert-deftest bytelocker-test-encrypt-decrypt-empty ()
  "Test encryption/decryption with empty content."
  (let ((content "")
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

(ert-deftest bytelocker-test-encrypt-decrypt-single-char ()
  "Test encryption/decryption with single character."
  (let ((content "X")
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

;;; ============================================================================
;;; Format Detection Tests
;;; ============================================================================

(ert-deftest bytelocker-test-is-file-encrypted ()
  "Test file encryption detection."
  (should (bytelocker--is-file-encrypted
           (concat bytelocker-file-header "\nbase64data\n" bytelocker-file-footer)))
  (should-not (bytelocker--is-file-encrypted "regular text"))
  (should-not (bytelocker--is-file-encrypted "")))

(ert-deftest bytelocker-test-is-encrypted ()
  "Test general encryption detection."
  (let ((encrypted (bytelocker--encrypt-for-file "test" "password" 'shift)))
    (should (bytelocker--is-encrypted encrypted))
    (should-not (bytelocker--is-encrypted "plain text"))))

;;; ============================================================================
;;; Edge Cases
;;; ============================================================================

(ert-deftest bytelocker-test-wrong-password ()
  "Test decryption with wrong password returns nil."
  (let* ((content "Secret message")
         (encrypted (bytelocker--encrypt-for-file content "correctpassword" 'shift)))
    (should-not (bytelocker--decrypt-from-file encrypted "wrongpassword" 'shift))))

(ert-deftest bytelocker-test-wrong-cipher ()
  "Test decryption with wrong cipher returns nil."
  (let* ((content "Secret message")
         (encrypted (bytelocker--encrypt-for-file content "password" 'shift)))
    (should-not (bytelocker--decrypt-from-file encrypted "password" 'xor))))

(ert-deftest bytelocker-test-different-passwords ()
  "Test that different passwords produce different outputs."
  (let ((content "Secret message"))
    (should-not (string= (bytelocker--encrypt-for-file content "password1" 'shift)
                         (bytelocker--encrypt-for-file content "password2" 'shift)))))

(ert-deftest bytelocker-test-different-ciphers ()
  "Test that different ciphers produce different outputs."
  (let ((content "Secret message")
        (password "testpassword"))
    (should-not (string= (bytelocker--encrypt-for-file content password 'shift)
                         (bytelocker--encrypt-for-file content password 'xor)))
    (should-not (string= (bytelocker--encrypt-for-file content password 'shift)
                         (bytelocker--encrypt-for-file content password 'caesar)))))

(ert-deftest bytelocker-test-long-content ()
  "Test encryption/decryption with long content."
  (let ((content (make-string 10000 ?x))
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

(ert-deftest bytelocker-test-binary-content ()
  "Test encryption/decryption with binary-like content."
  (let ((content (apply #'string (number-sequence 0 255)))
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

;;; ============================================================================
;;; Padding Tests
;;; ============================================================================

(ert-deftest bytelocker-test-padding-block-size ()
  "Test padding to block size."
  (should (= (length (bytelocker--pad-to-block-size '(1 2 3)))
             bytelocker-cipher-block-size))
  (should (= (length (bytelocker--pad-to-block-size (make-list bytelocker-cipher-block-size 1)))
             bytelocker-cipher-block-size))
  (should (= (length (bytelocker--pad-to-block-size (make-list (1+ bytelocker-cipher-block-size) 1)))
             (* 2 bytelocker-cipher-block-size))))

(ert-deftest bytelocker-test-padding-preserves-content ()
  "Test that padding preserves original content."
  (let* ((original '(1 2 3))
         (padded (bytelocker--pad-to-block-size original)))
    (should (equal (cl-subseq padded 0 3) original))))

;;; ============================================================================
;;; Integration Tests
;;; ============================================================================

(ert-deftest bytelocker-test-deterministic-encryption ()
  "Test that encryption is deterministic."
  (let ((content "Test content")
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= (bytelocker--encrypt-for-file content password cipher)
                       (bytelocker--encrypt-for-file content password cipher))))))

(ert-deftest bytelocker-test-special-characters ()
  "Test encryption/decryption with special characters."
  (let ((content "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\\n\t\r")
        (password "testpassword"))
    (dolist (cipher '(shift xor caesar))
      (should (string= content
                       (bytelocker--decrypt-from-file
                        (bytelocker--encrypt-for-file content password cipher)
                        password cipher))))))

(provide 'bytelocker-test)

;;; bytelocker-test.el ends here
