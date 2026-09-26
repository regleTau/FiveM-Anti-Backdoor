// Visual combat effects: muzzle flash, tracers, impacts, decals, blood,
// smoke and particles. Other systems call these hooks.
import * as THREE from 'three';

export class Effects {
  constructor(game) {
    this.game = game;
    this.items = [];
  }

  impact(point, normal) {
    const m = new THREE.Mesh(new THREE.SphereGeometry(0.03), new THREE.MeshBasicMaterial({ color: 0xffcc88 }));
    m.position.copy(point);
    this.game.scene.add(m);
    this.items.push({ obj: m, life: 0.15 });
  }

  blood(point) { this.impact(point); }

  muzzleFlash() {}

  update(dt) {
    for (let i = this.items.length - 1; i >= 0; i--) {
      const it = this.items[i];
      it.life -= dt;
      if (it.life <= 0) {
        this.game.scene.remove(it.obj);
        this.items.splice(i, 1);
      }
    }
  }
}
