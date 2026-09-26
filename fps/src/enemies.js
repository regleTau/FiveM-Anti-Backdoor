// Enemy soldiers: spawning, AI (patrol, take cover, shoot), damage, death.
import * as THREE from 'three';

export class Enemies {
  constructor(game) {
    this.game = game;
    this.list = [];
    this.raycaster = new THREE.Raycaster();
  }

  init() {
    for (const sp of this.game.world.spawnPoints) this.spawn(sp);
  }

  spawn(at) {
    const mat = new THREE.MeshStandardMaterial({ color: 0x4a5040, roughness: 0.8 });
    const mesh = new THREE.Mesh(new THREE.CapsuleGeometry(0.35, 1.1, 4, 8), mat);
    mesh.position.copy(at).setY(0.9);
    mesh.castShadow = true;
    this.game.scene.add(mesh);
    const e = { mesh, health: 100, alive: true, fireCd: 1 + Math.random() };
    mesh.userData.enemy = e;
    this.list.push(e);
  }

  raycast(origin, dir) {
    this.raycaster.set(origin, dir);
    const hits = this.raycaster.intersectObjects(this.list.filter((e) => e.alive).map((e) => e.mesh), true);
    return hits[0] || null;
  }

  hit(intersection, dmg) {
    let o = intersection.object;
    while (o && !o.userData.enemy) o = o.parent;
    const e = o?.userData.enemy;
    if (!e || !e.alive) return;
    e.health -= dmg;
    if (e.health <= 0) {
      e.alive = false;
      e.mesh.rotation.z = Math.PI / 2;
      e.mesh.position.y = 0.35;
      this.game.hud.onKill?.();
    }
  }

  update(dt, paused) {
    if (paused) return;
    const eye = this.game.player.eye;
    for (const e of this.list) {
      if (!e.alive) continue;
      e.mesh.lookAt(eye.x, e.mesh.position.y, eye.z);
      e.fireCd -= dt;
      if (e.fireCd <= 0) {
        e.fireCd = 0.8 + Math.random();
        const from = e.mesh.position.clone().setY(1.5);
        const dir = eye.clone().sub(from);
        const dist = dir.length();
        dir.normalize();
        const block = this.game.world.raycast(from, dir, dist);
        if (!block && Math.random() < 0.3) this.game.player.damage(8);
      }
    }
  }
}
