// Viewmodel weapons: firing, recoil, ADS, reload, hitscan.
// The viewmodel lives in `this.viewScene` and is rendered by the renderer
// on top of the world with its own camera (`this.viewCamera`).
import * as THREE from 'three';

export class Weapons {
  constructor(game) {
    this.game = game;
    this.viewScene = new THREE.Scene();
    this.viewCamera = new THREE.PerspectiveCamera(55, 1, 0.01, 10);
    this.adsFactor = 0;
    this.cooldown = 0;
    this.ammo = 30;
    this.reserve = 120;
    this.magSize = 30;
    this.reloading = 0;
    this.recoil = 0;
  }

  init() {
    const gun = new THREE.Group();
    const mat = new THREE.MeshStandardMaterial({ color: 0x2a2a2a, roughness: 0.5, metalness: 0.6 });
    const body = new THREE.Mesh(new THREE.BoxGeometry(0.06, 0.08, 0.45), mat);
    const barrel = new THREE.Mesh(new THREE.CylinderGeometry(0.012, 0.012, 0.3), mat);
    barrel.rotation.x = Math.PI / 2;
    barrel.position.set(0, 0.02, -0.35);
    gun.add(body, barrel);
    gun.position.set(0.18, -0.16, -0.4);
    this.gun = gun;
    this.viewScene.add(gun);
    this.viewScene.add(new THREE.HemisphereLight(0xffffff, 0x444444, 1.5));
    const key = new THREE.DirectionalLight(0xffffff, 2);
    key.position.set(1, 2, 1);
    this.viewScene.add(key);
  }

  update(dt, paused) {
    const { input } = this.game;
    this.viewCamera.aspect = this.game.camera.aspect;
    this.viewCamera.updateProjectionMatrix();
    this.cooldown -= dt;
    if (!paused) {
      this.adsFactor += ((input.mouse.right ? 1 : 0) - this.adsFactor) * Math.min(1, 12 * dt);
      if (input.wasPressed('KeyR') && this.ammo < this.magSize && this.reserve > 0 && this.reloading <= 0) this.reloading = 2.2;
      if (this.reloading > 0) {
        this.reloading -= dt;
        if (this.reloading <= 0) {
          const take = Math.min(this.magSize - this.ammo, this.reserve);
          this.ammo += take; this.reserve -= take;
        }
      } else if (input.mouse.left && this.cooldown <= 0 && this.ammo > 0) this.fire();
    }
    this.recoil *= Math.exp(-10 * dt);
    this.game.camera.fov = 72 - 18 * this.adsFactor;
    this.game.camera.updateProjectionMatrix();
    const hip = new THREE.Vector3(0.18, -0.16, -0.4), ads = new THREE.Vector3(0, -0.07, -0.3);
    this.gun.position.lerpVectors(hip, ads, this.adsFactor);
    this.gun.position.z += this.recoil * 0.06;
  }

  fire() {
    this.cooldown = 60 / 750;
    this.ammo--;
    this.recoil = 1;
    const p = this.game.player;
    p.pitch += 0.012 * (1 - 0.5 * this.adsFactor);
    const cam = this.game.camera;
    const origin = cam.getWorldPosition(new THREE.Vector3());
    const dir = cam.getWorldDirection(new THREE.Vector3());
    const spread = 0.02 * (1 - this.adsFactor) + 0.002;
    dir.x += (Math.random() - 0.5) * spread;
    dir.y += (Math.random() - 0.5) * spread;
    dir.normalize();
    const enemyHit = this.game.enemies.raycast(origin, dir);
    const worldHit = this.game.world.raycast(origin, dir);
    if (enemyHit && (!worldHit || enemyHit.distance < worldHit.distance)) {
      this.game.enemies.hit(enemyHit, 34);
      this.game.effects.blood?.(enemyHit.point, dir);
      this.game.hud.hitmarker?.();
    } else if (worldHit) {
      this.game.effects.impact?.(worldHit.point, worldHit.face?.normal, worldHit.object);
    }
    this.game.effects.muzzleFlash?.();
    this.game.audio.play?.('rifle');
  }
}
