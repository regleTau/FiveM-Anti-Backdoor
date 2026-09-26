// Shared PBR material library. `getMaterial(name)` returns a cached
// THREE.MeshStandardMaterial (or MeshPhysicalMaterial). World, props and
// enemies use these names; the set of names is the public API:
//   concrete, concrete_dark, brick, plaster, asphalt, dirt, gravel,
//   metal_painted, metal_rusty, metal_bare, wood, wood_crate, glass,
//   sandbag, tarp, rubber, cloth_camo, cloth_dark, skin, gunmetal, polymer
// Textures should be world-scale: UVs of 1 unit = 1 metre, so callers can
// use `worldUV(geometry)` or set repeat to match the object's size.
import * as THREE from 'three';

const cache = new Map();
const BASE = {
  concrete: 0x8f8b84, concrete_dark: 0x5e5b56, brick: 0x8a4a38, plaster: 0xb8ad9a,
  asphalt: 0x3a3a3c, dirt: 0x6b5a45, gravel: 0x7a7468, metal_painted: 0x4d5a4a,
  metal_rusty: 0x6e4a32, metal_bare: 0x9a9a9a, wood: 0x6e5236, wood_crate: 0x8a6a40,
  glass: 0x223038, sandbag: 0x9a8a68, tarp: 0x3f4a3a, rubber: 0x1a1a1a,
  cloth_camo: 0x4f5540, cloth_dark: 0x2c2e2a, skin: 0xb08a70, gunmetal: 0x2a2b2d, polymer: 0x1e1f1f,
};

export function getMaterial(name) {
  if (cache.has(name)) return cache.get(name);
  const metal = name.startsWith('metal') || name === 'gunmetal';
  const m = new THREE.MeshStandardMaterial({
    color: BASE[name] ?? 0xff00ff,
    roughness: metal ? 0.45 : 0.9,
    metalness: metal ? 0.8 : 0,
  });
  m.name = name;
  cache.set(name, m);
  return m;
}

// Rewrites a geometry's UVs as box-projected world-space metres, so a
// shared texture tiles consistently regardless of object size.
export function worldUV(geometry, scale = 1) {
  const pos = geometry.attributes.position;
  const nor = geometry.attributes.normal;
  const uv = new Float32Array(pos.count * 2);
  for (let i = 0; i < pos.count; i++) {
    const ax = Math.abs(nor.getX(i)), ay = Math.abs(nor.getY(i)), az = Math.abs(nor.getZ(i));
    let u, v;
    if (ay >= ax && ay >= az) { u = pos.getX(i); v = pos.getZ(i); }
    else if (ax >= az) { u = pos.getZ(i); v = pos.getY(i); }
    else { u = pos.getX(i); v = pos.getY(i); }
    uv[i * 2] = u * scale;
    uv[i * 2 + 1] = v * scale;
  }
  geometry.setAttribute('uv', new THREE.BufferAttribute(uv, 2));
  return geometry;
}
