#!/bin/sh
# run-tests.sh — load secp256k1-fast and run its self-test suite.
# Pure SBCL, no external dependencies. Exits NON-ZERO on any test failure.
#
# Makes this repo visible to ASDF for the duration of the run by pushing its
# own directory onto the central registry, so it works whether or not the repo
# is symlinked into ~/quicklisp/local-projects.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)

SBCL=${SBCL:-sbcl}

exec "$SBCL" --non-interactive \
  --eval "(require :asdf)" \
  --eval "(push #p\"$HERE/\" asdf:*central-registry*)" \
  --eval '(handler-case
            (progn
              (asdf:load-system "secp256k1-fast/test")
              ;; resolve at runtime — package does not exist when this form is read.
              ;; run-all signals an error on any failing check, else returns T.
              (if (uiop:symbol-call :secp256k1-fast.test :run-all)
                  (progn (format t "~&run-tests.sh: PASS~%") (sb-ext:exit :code 0))
                  (progn (format t "~&run-tests.sh: FAIL~%") (sb-ext:exit :code 1))))
            (error (e)
              (format t "~&run-tests.sh: FAIL -- ~a~%" e)
              (sb-ext:exit :code 1)))'
