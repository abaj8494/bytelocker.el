EMACS ?= $(shell command -v emacs 2>/dev/null || echo "/Applications/MacPorts/Emacs.app/Contents/MacOS/Emacs")

.PHONY: test test-verbose clean lint coverage coverage-html

test:
	$(EMACS) --batch -l ert -l bytelocker.el -l bytelocker-test.el -f ert-run-tests-batch-and-exit

test-verbose:
	$(EMACS) --batch -l ert -l bytelocker.el -l bytelocker-test.el --eval "(ert-run-tests-batch-and-exit '(not (tag :slow)))"

lint:
	$(EMACS) --batch -l bytelocker.el -f byte-compile-file bytelocker.el

clean:
	rm -f *.elc coverage/*.json

coverage:
	@mkdir -p coverage
	cd $(CURDIR) && $(EMACS) --batch --eval "\
	(progn \
	  (add-to-list 'load-path \".\") \
	  (require 'package) \
	  (add-to-list 'package-archives '(\"melpa\" . \"https://melpa.org/packages/\") t) \
	  (package-initialize) \
	  (unless (package-installed-p 'undercover) \
	    (package-refresh-contents) \
	    (package-install 'undercover)) \
	  (require 'undercover) \
	  (setq undercover-force-coverage t) \
	  (undercover \"bytelocker.el\" (:report-format 'text) (:send-report nil)) \
	  (require 'bytelocker) \
	  (require 'ert) \
	  (load \"bytelocker-test\") \
	  (ert-run-tests-batch-and-exit))"

coverage-lcov:
	@mkdir -p coverage
	cd $(CURDIR) && $(EMACS) --batch --eval "\
	(progn \
	  (add-to-list 'load-path \".\") \
	  (require 'package) \
	  (add-to-list 'package-archives '(\"melpa\" . \"https://melpa.org/packages/\") t) \
	  (package-initialize) \
	  (unless (package-installed-p 'undercover) \
	    (package-refresh-contents) \
	    (package-install 'undercover)) \
	  (require 'undercover) \
	  (setq undercover-force-coverage t) \
	  (undercover \"bytelocker.el\" \
	              (:report-format 'lcov) \
	              (:report-file \"coverage/lcov.info\") \
	              (:send-report nil)) \
	  (require 'bytelocker) \
	  (require 'ert) \
	  (load \"bytelocker-test\") \
	  (ert-run-tests-batch-and-exit))"
	@echo "Coverage report written to coverage/lcov.info"
