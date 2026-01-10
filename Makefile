EMACS ?= $(shell command -v emacs 2>/dev/null || echo "/Applications/MacPorts/Emacs.app/Contents/MacOS/Emacs")

.PHONY: test test-verbose clean lint coverage

test:
	$(EMACS) --batch -l ert -l bytelocker.el -l bytelocker-test.el -f ert-run-tests-batch-and-exit

test-verbose:
	$(EMACS) --batch -l ert -l bytelocker.el -l bytelocker-test.el --eval "(ert-run-tests-batch-and-exit '(not (tag :slow)))"

lint:
	$(EMACS) --batch -l bytelocker.el -f byte-compile-file bytelocker.el

clean:
	rm -f *.elc

coverage:
	@echo "Run tests with undercover.el for coverage reporting:"
	@echo '  $(EMACS) --batch -l undercover -l bytelocker.el -l bytelocker-test.el -f ert-run-tests-batch-and-exit'
