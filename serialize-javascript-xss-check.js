/**
 * GHSA-m5mm-p8h7-m29v (CWE-79): asserts the installed release emits no unterminated `</script` from a
 * function body ending exactly at that prefix. Payload strings are inert unless a consumer serializes them;
 * the file writes nothing to disk and is a check, not an indexed scanner fixture, so a scanner report on
 * the literal payload is expected, unreconciled. Usage: node serialize-javascript-xss-check.js <dir> or
 * SERIALIZE_JAVASCRIPT_DIR=<dir>, one required, which must hold an installed copy because this checkout
 * never holds node_modules. Longer than the specified ~40 lines: the argument contract, the
 * installed-version read and the flush-safe failure path need their lines; none of the surplus is padding.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { createRequire } = require('module');

const PACKAGE = 'serialize-javascript';
const CLOSING_SCRIPT = /<\/script/i;

class CheckFailure extends Error {}
const fail = (message) => { throw new CheckFailure(message); };

// The installed copy's own manifest, never this repository's declaration.
function installedVersion(requireFromInstall, entryFile) {
  let manifestPath;
  try {
    manifestPath = requireFromInstall.resolve(PACKAGE + '/package.json');
  } catch (error) {
    manifestPath = path.join(path.dirname(entryFile), 'package.json');
  }
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8')).version;
}

try {
  // First argument over the environment variable; a blank value counts as absent for both.
  const givenDir = [process.argv[2], process.env.SERIALIZE_JAVASCRIPT_DIR].find((value) => value && value.trim() !== '');
  if (!givenDir) fail('no install directory given (pass it as the first argument or set SERIALIZE_JAVASCRIPT_DIR)');
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
  if (!output.includes('function(){}')) fail('serialized output does not contain the function source text: ' + output);
  if (CLOSING_SCRIPT.test(output)) fail('serialized function source still contains a bare closing-script prefix: ' + output);
  const stringOutput = serialize({ markup: '</script' });
  const stillEscaped = !CLOSING_SCRIPT.test(stringOutput) && stringOutput.includes('\\u003C');
  if (!stillEscaped) fail('a closing-script sequence inside a string value is no longer escaped: ' + stringOutput);
  console.log('PASS: closing-script prefix neutralised (GHSA-m5mm-p8h7-m29v)');
} catch (error) {
  const detail = error instanceof CheckFailure
    ? error.message
    : 'unexpected error: ' + (error && error.stack ? error.stack : String(error));
  // Setting exitCode instead of calling process.exit() lets a piped stderr flush before exit.
  console.error('FAIL: ' + detail);
  process.exitCode = 1;
}
