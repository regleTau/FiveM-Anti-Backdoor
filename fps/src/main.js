// Entry point. Owns the game loop and wires the subsystems together.
// Each subsystem is a class with `constructor(game)`, optional `async init()`
// and optional `update(dt)`; they reach each other through `game`.
import * as THREE from 'three';
import { Renderer } from './renderer.js';
import { World } from './world.js';
import { Player } from './player.js';
import { Weapons } from './weapons.js';
import { Enemies } from './enemies.js';
import { Effects } from './effects.js';
import { Audio } from './audio.js';
import { Hud } from './hud.js';
import { Input } from './input.js';
import { ShotMode } from './shotmode.js';

class Game {
  constructor() {
    this.params = new URLSearchParams(location.search);
    this.canvas = document.getElementById('game');
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(72, innerWidth / innerHeight, 0.03, 1500);
    this.clock = new THREE.Clock();
    this.time = 0;
    this.paused = true;

    this.input = new Input(this);
    this.renderer = new Renderer(this);
    this.world = new World(this);
    this.effects = new Effects(this);
    this.audio = new Audio(this);
    this.player = new Player(this);
    this.weapons = new Weapons(this);
    this.enemies = new Enemies(this);
    this.hud = new Hud(this);
    this.shotMode = new ShotMode(this);

    this.systems = [
      this.input, this.world, this.player, this.weapons, this.enemies,
      this.effects, this.audio, this.hud, this.shotMode,
    ];
  }

  async init() {
    await this.renderer.init();
    for (const s of this.systems) if (s.init) await s.init();
    addEventListener('resize', () => this.onResize());
    this.onResize();
    window.__game = this;
    window.__ready = true;
    this.renderer.renderer.setAnimationLoop(() => this.frame());
  }

  onResize() {
    this.camera.aspect = innerWidth / innerHeight;
    this.camera.updateProjectionMatrix();
    this.renderer.resize(innerWidth, innerHeight);
  }

  frame() {
    const dt = Math.min(this.clock.getDelta(), 1 / 20);
    this.step(dt);
    this.renderer.render(dt);
  }

  step(dt) {
    this.time += dt;
    for (const s of this.systems) if (s.update) s.update(dt, this.paused);
  }
}

new Game().init();
