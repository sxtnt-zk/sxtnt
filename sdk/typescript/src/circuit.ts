/**
 * Circuit template loader.
 *
 * The SXTNT marketplace ships a small catalogue of reusable circuit
 * templates — verifiable inference, range checks, signature
 * aggregation. Each template ships as a JSON manifest that names the
 * scheme, the public-input shape, and a stable id.
 *
 * The loader does two things:
 *
 *   • Validates an incoming manifest against the canonical shape.
 *   • Computes a deterministic digest of the manifest so a client can
 *     pin the exact version it expects.
 *
 * Heavier circuit compilation (R1CS / CCS generation, witness solving)
 * happens off-chain and is out of scope for this SDK.
 */

import { blake3 } from "@noble/hashes/blake3";
import { SchemeKind } from "./types.js";

/** The shape every circuit template manifest must satisfy. */
export interface CircuitTemplate {
  /** Stable identifier — kebab-case slug, must be unique within the
   *  marketplace. */
  id: string;
  /** Human-readable label. */
  name: string;
  /** Folding scheme this template is parameterised for. */
  scheme: SchemeKind;
  /** Number of public inputs the template exposes. */
  publicInputs: number;
  /** Number of rows in the R1CS (or CCS) instance the template
   *  generates. */
  rows: number;
  /** Free-text description shown in the marketplace UI. */
  description: string;
  /** Semver of the template definition. */
  version: string;
}

/** Loader. Stateless — the methods take a manifest each time. */
export class CircuitLoader {
  /** Parse a JSON string into a `CircuitTemplate`. Throws on
   *  validation failures so callers cannot silently process a
   *  malformed manifest. */
  static parse(json: string): CircuitTemplate {
    const raw: unknown = JSON.parse(json);
    if (!raw || typeof raw !== "object") {
      throw new Error("circuit template must be a JSON object");
    }
    const obj = raw as Record<string, unknown>;
    assertString(obj, "id");
    assertString(obj, "name");
    assertString(obj, "description");
    assertString(obj, "version");
    assertNumber(obj, "publicInputs");
    assertNumber(obj, "rows");
    assertNumber(obj, "scheme");
    const scheme = obj.scheme as number;
    if (![SchemeKind.Nova, SchemeKind.SuperNova, SchemeKind.HyperNova].includes(scheme)) {
      throw new Error(`unknown scheme: ${scheme}`);
    }
    const id = obj.id as string;
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(id)) {
      throw new Error(`invalid template id: ${id}`);
    }
    return {
      id,
      name: obj.name as string,
      scheme: scheme as SchemeKind,
      publicInputs: obj.publicInputs as number,
      rows: obj.rows as number,
      description: obj.description as string,
      version: obj.version as string,
    };
  }

  /** Compute the canonical digest of a manifest. The on-chain
   *  marketplace records this digest so two clients that name the
   *  same id always check against the same definition. */
  static digest(template: CircuitTemplate): Uint8Array {
    const h = blake3.create({});
    h.update(new TextEncoder().encode("sxtnt.circuit.v1"));
    h.update(new TextEncoder().encode(template.id));
    h.update(new TextEncoder().encode(template.version));
    h.update(new Uint8Array([template.scheme]));
    h.update(uint32LE(template.publicInputs));
    h.update(uint32LE(template.rows));
    h.update(new TextEncoder().encode(template.name));
    h.update(new TextEncoder().encode(template.description));
    return h.digest();
  }

  /** Convenience: load a template from a manifest URL via `fetch`. */
  static async fetch(url: string): Promise<CircuitTemplate> {
    const res = await globalThis.fetch(url);
    if (!res.ok) {
      throw new Error(`failed to fetch circuit template: ${res.status}`);
    }
    return CircuitLoader.parse(await res.text());
  }
}

function assertString(obj: Record<string, unknown>, key: string): void {
  if (typeof obj[key] !== "string") {
    throw new Error(`circuit template field "${key}" must be a string`);
  }
}

function assertNumber(obj: Record<string, unknown>, key: string): void {
  if (typeof obj[key] !== "number" || !Number.isFinite(obj[key] as number)) {
    throw new Error(`circuit template field "${key}" must be a finite number`);
  }
}

function uint32LE(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}
// adjust the constant carefully — the digest depends on it.
