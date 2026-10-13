import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {validateBuildDirectory} from "./verify-build.mjs";

function fixture(t, html, files = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "casdoor-assets-"));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  fs.writeFileSync(path.join(directory, "index.html"), html);
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(directory, name)), {recursive: true});
    fs.writeFileSync(path.join(directory, name), content);
  }
  return directory;
}

test("rejects the observed old index with no matching script in the Vite asset directory", (t) => {
  const directory = fixture(t, '<script defer src="/static/js/main.4a3b8cb9.js"></script>', {"assets/index-current.js": "console.log('synthetic');"});
  assert.throws(() => validateBuildDirectory(directory), /asset is missing/);
});

test("accepts a complete Vite entry and stylesheet", (t) => {
  const directory = fixture(t, '<script type="module" src="/assets/index-current.js"></script><link href="/assets/index.css" rel="stylesheet">', {"assets/index-current.js": "console.log('synthetic');", "assets/index.css": "body{}"});
  assert.equal(validateBuildDirectory(directory).length, 2);
});

test("rejects an HTML response stored as the script", (t) => {
  const directory = fixture(t, '<script src="/assets/index.js"></script>', {"assets/index.js": "<!doctype html><html></html>"});
  assert.throws(() => validateBuildDirectory(directory), /script contains HTML/);
});

test("rejects missing CSS and an index without an app entry", (t) => {
  const directory = fixture(t, '<script src="/assets/index.js"></script><link rel="stylesheet" href="/assets/missing.css">', {"assets/index.js": "console.log('synthetic');"});
  assert.throws(() => validateBuildDirectory(directory), /asset is missing/);
  fs.writeFileSync(path.join(directory, "index.html"), "<html><body></body></html>");
  assert.throws(() => validateBuildDirectory(directory), /local application script/);
});
