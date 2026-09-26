// Deterministic camera poses for automated screenshots / visual review.
// `?shot=<name>` hides the menu, places the camera, and sets
// window.__shotReady once enough frames have rendered.
// Also ends each input frame (runs last in the system list).
import * as THREE from 'three';

export const SHOTS = {
  overview: { pos: [0, 1.6, 20], yaw: 0, pitch: -0.05 },
  street: { pos: [-8, 1.6, 10], yaw: -0.6, pitch: 0 },
  cover: { pos: [4, 1.6, 2], yaw: 0.3, pitch: -0.02 },
  weapon: { pos: [0, 1.6, 20], yaw: 0.4, pitch: -0.1, ads: 0 },
  ads: { pos: [0, 1.6, 20], yaw: 0, pitch: 0, ads: 1 },
  combat: { pos: [0, 1.6, 12], yaw: 0, pitch: 0, fire: true },
  sky: { pos: [0, 1.6, 20], yaw: 2.5, pitch: 0.35 },
};

export class ShotMode {
  constructor(game) {
    this.game = game;
    this.name = game.params.get('shot');
    this.frames = 0;
  }

  init() {
    if (!this.name) return;
    document.getElementById('menu').style.display = 'none';
    this.game.paused = false;
  }

  update() {
    const g = this.game;
    g.input.endFrame();
    if (!this.name) return;
    const s = SHOTS[this.name] || SHOTS.overview;
    g.player.pos.set(s.pos[0], s.pos[1] - 1.6, s.pos[2]);
    g.player.vel.set(0, 0, 0);
    g.player.yaw = s.yaw;
    g.player.pitch = s.pitch;
    g.input.mouse.right = !!s.ads;
    g.input.mouse.left = !!s.fire && this.frames > 20 && this.frames < 40;
    g.camera.position.copy(g.player.eye);
    g.camera.rotation.set(s.pitch, s.yaw, 0, 'YXZ');
    this.frames++;
    if (this.frames === 45) window.__shotReady = true;
  }
}

export { THREE };
