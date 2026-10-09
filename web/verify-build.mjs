import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

// Validate the actual HTML-to-asset contract before replacing the previous build.
export function validateBuildDirectory(directory) {
  const root = path.resolve(directory);
  const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)].map((match) => match[1]);
  const styles = [...html.matchAll(/<link\b[^>]*>/gi)]
    .filter((match) => /\brel\s*=\s*["']stylesheet["']/i.test(match[0]))
    .map((match) => match[0].match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1])
    .filter(Boolean);
  const localScripts = scripts.filter((reference) => !/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(reference));
  if (localScripts.length === 0) {
    throw new Error("Frontend index.html must reference a local application script");
  }
  const checked = [];
  for (const reference of [...localScripts, ...styles]) {
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(reference)) {
      continue;
    }
    const assetPath = decodeURIComponent(reference.split(/[?#]/, 1)[0]).replace(/^\/+/, "");
    const resolved = path.resolve(root, assetPath);
    if (!resolved.startsWith(root + path.sep) || !fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
      throw new Error(`Frontend asset is missing or outside the build directory: ${reference}`);
    }
    if (/\.m?js$/i.test(assetPath) && /^\s*(?:<!doctype\s+html|<html\b)/i.test(fs.readFileSync(resolved, "utf8"))) {
      throw new Error(`Frontend script contains HTML: ${reference}`);
    }
    checked.push(reference);
  }
  return checked;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = process.argv[2] || path.join(path.dirname(fileURLToPath(import.meta.url)), "build");
  const assets = validateBuildDirectory(directory);
  console.log(`Frontend asset contract PASS: ${assets.length} local assets`);
}
