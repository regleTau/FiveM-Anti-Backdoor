// WebGL renderer, shadows, environment lighting and post-processing.
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';

export class Renderer {
  constructor(game) {
    this.game = game;
  }

  async init() {
    const r = new THREE.WebGLRenderer({ canvas: this.game.canvas, antialias: false, powerPreference: 'high-performance' });
    r.setPixelRatio(Math.min(devicePixelRatio, 2));
    r.shadowMap.enabled = true;
    r.shadowMap.type = THREE.PCFSoftShadowMap;
    r.toneMapping = THREE.ACESFilmicToneMapping;
    r.toneMappingExposure = 1.0;
    r.outputColorSpace = THREE.SRGBColorSpace;
    this.renderer = r;

    const scene = this.game.scene;
    scene.background = new THREE.Color(0x9fb4c8);
    scene.fog = new THREE.FogExp2(0xa8b6c2, 0.006);

    const hemi = new THREE.HemisphereLight(0xcfe0ff, 0x5a4a3a, 0.8);
    scene.add(hemi);
    const sun = new THREE.DirectionalLight(0xfff0dd, 3.0);
    sun.position.set(60, 90, 40);
    sun.castShadow = true;
    sun.shadow.mapSize.set(2048, 2048);
    Object.assign(sun.shadow.camera, { left: -80, right: 80, top: 80, bottom: -80, near: 1, far: 300 });
    sun.shadow.bias = -0.0004;
    scene.add(sun);
    this.sun = sun;

    const composer = new EffectComposer(r);
    composer.addPass(new RenderPass(scene, this.game.camera));
    composer.addPass(new OutputPass());
    this.composer = composer;
  }

  resize(w, h) {
    this.renderer.setSize(w, h, false);
    this.composer.setSize(w, h);
  }

  render(dt) {
    this.composer.render(dt);
    // Viewmodel on top of the world with its own depth range.
    const w = this.game.weapons;
    if (w?.viewScene) {
      const r = this.renderer;
      r.autoClear = false;
      r.clearDepth();
      r.render(w.viewScene, w.viewCamera);
      r.autoClear = true;
    }
  }
}
