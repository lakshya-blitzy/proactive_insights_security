#!/usr/bin/env node
/**
 * Security check: GHSA-m5mm-p8h7-m29v (CWE-79) in serialize-javascript < 7.1.3.
 *
 * Releases below 7.1.3 escape each serialized function body in isolation, so a body whose
 * source ends exactly at the bare closing-script prefix leaves an unterminated `</script`
 * in the output. This script serializes such a body and fails if a closing-script sequence
 * survives, proving the installed release neutralises the payload and not merely that the
 * manifest declares a newer version.
 *
 * The payload strings below are inert unless a consumer serializes them, and this file
 * writes nothing to disk. It is a check rather than a scanner fixture, so it is absent
 * from security_fixture/README.md by decision: a scanner may still report its literal
 * payload, which is an expected and unreconciled finding.
 *
 * Usage: node serialize-javascript-xss-check.js <install dir>
 *        SERIALIZE_JAVASCRIPT_DIR=<install dir> node serialize-javascript-xss-check.js
 * <install dir> must contain an installed copy of the package; this checkout never holds
 * node_modules, so the directory is required and no bare require is attempted.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { createRequire } = require('module');

const PACKAGE = 'serialize-javascript';
const ADVISORY = 'GHSA-m5mm-p8h7-m29v';
const CLOSING_SCRIPT = /<\/script/i;

class CheckFailure extends Error {}

/** Aborts the check with a message that is printed verbatim after the `FAIL: ` prefix. */
function fail(message) {
  throw new CheckFailure(message);
}

/** The required install directory: first argument, else the environment variable. */
function installDir() {
  const fromArgument = process.argv[2];
  if (fromArgument && fromArgument.trim() !== '') {
    return fromArgument;
  }
  const fromEnvironment = process.env.SERIALIZE_JAVASCRIPT_DIR;
  if (fromEnvironment && fromEnvironment.trim() !== '') {
    return fromEnvironment;
  }
  fail('no install directory given (pass it as the first argument or set SERIALIZE_JAVASCRIPT_DIR)');
}

/** The version of the copy actually installed, never this repository's declaration. */
function installedVersion(requireFromInstall, entryFile) {
  let manifestPath;
  try {
    manifestPath = requireFromInstall.resolve(PACKAGE + '/package.json');
  } catch (error) {
    manifestPath = path.join(path.dirname(entryFile), 'package.json');
  }
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8')).version;
}

function check(givenDir) {
  const requireFromInstall = createRequire(path.join(path.resolve(givenDir), 'noop.js'));
  let entryFile;
  try {
    entryFile = requireFromInstall.resolve(PACKAGE);
  } catch (error) {
    fail('cannot resolve ' + PACKAGE + ' from ' + givenDir);
  }
  const serialize = requireFromInstall(PACKAGE);
  console.log(PACKAGE + ' version: ' + installedVersion(requireFromInstall, entryFile));

  const handler = function () {};
  handler.toString = () => 'function(){}</script';
  const output = serialize({ handler: handler, markup: '><img src=x onerror=alert(1)>' });

  if (!output.includes('function(){}')) {
    fail('serialized output does not contain the function source text: ' + output);
  }
  if (CLOSING_SCRIPT.test(output)) {
    fail('serialized function source still contains a bare closing-script prefix: ' + output);
  }
  const stringOutput = serialize({ markup: '</script' });
  if (CLOSING_SCRIPT.test(stringOutput) || !stringOutput.includes('\\u003C')) {
    fail('a closing-script sequence inside a string value is no longer escaped: ' + stringOutput);
  }

  console.log('PASS: closing-script prefix neutralised (' + ADVISORY + ')');
}

try {
  check(installDir());
} catch (error) {
  const detail =
    error instanceof CheckFailure
      ? error.message
      : 'unexpected error: ' + (error && error.stack ? error.stack : String(error));
  // Writing through console.error and setting exitCode lets the stream flush before exit,
  // where process.exit() could truncate the message when stderr is a pipe.
  console.error('FAIL: ' + detail);
  process.exitCode = 1;
}
