// First-person controller: look, walk/sprint/crouch/jump, gravity and
// AABB collision against world.colliders.
import * as THREE from 'three';

const STAND = 1.7, CROUCH = 1.1, RADIUS = 0.35;

export class Player {
  constructor(game) {
    this.game = game;
    this.pos = new THREE.Vector3();
    this.vel = new THREE.Vector3();
    this.yaw = 0;
    this.pitch = 0;
    this.height = STAND;
    this.onGround = false;
    this.health = 100;
    this.sprinting = false;
    this.moving = false;
    this.sensitivity = 0.0022;
  }

  init() {
    this.pos.copy(this.game.world.playerSpawn);
  }

  get eye() { return new THREE.Vector3(this.pos.x, this.pos.y + this.height - 0.1, this.pos.z); }

  update(dt, paused) {
    const { input, camera } = this.game;
    if (!paused) {
      const { dx, dy } = input.consumeMouse();
      const s = this.sensitivity * (this.game.weapons?.adsFactor ? 1 - 0.4 * this.game.weapons.adsFactor : 1);
      this.yaw -= dx * s;
      this.pitch = THREE.MathUtils.clamp(this.pitch - dy * s, -1.5, 1.5);

      const fwd = (input.down('KeyW') ? 1 : 0) - (input.down('KeyS') ? 1 : 0);
      const str = (input.down('KeyD') ? 1 : 0) - (input.down('KeyA') ? 1 : 0);
      const crouch = input.down('ControlLeft') || input.down('KeyC');
      this.sprinting = input.down('ShiftLeft') && fwd > 0 && !crouch;
      const speed = crouch ? 2.2 : this.sprinting ? 7.2 : 4.6;

      const wish = new THREE.Vector3(str, 0, -fwd);
      if (wish.lengthSq() > 0) wish.normalize().applyAxisAngle(new THREE.Vector3(0, 1, 0), this.yaw).multiplyScalar(speed);
      this.moving = wish.lengthSq() > 0;
      const accel = this.onGround ? 12 : 2;
      this.vel.x += (wish.x - this.vel.x) * Math.min(1, accel * dt);
      this.vel.z += (wish.z - this.vel.z) * Math.min(1, accel * dt);
      if (this.onGround && input.wasPressed('Space')) { this.vel.y = 5.2; this.onGround = false; }
      this.height += ((crouch ? CROUCH : STAND) - this.height) * Math.min(1, 10 * dt);
    }

    this.vel.y -= 16 * dt;
    this.moveAxis('x', this.vel.x * dt);
    this.moveAxis('z', this.vel.z * dt);
    this.onGround = false;
    this.moveAxis('y', this.vel.y * dt);
    if (this.pos.y <= 0) { this.pos.y = 0; this.vel.y = 0; this.onGround = true; }

    camera.position.copy(this.eye);
    camera.rotation.set(this.pitch, this.yaw, 0, 'YXZ');
  }

  moveAxis(axis, d) {
    this.pos[axis] += d;
    const box = new THREE.Box3(
      new THREE.Vector3(this.pos.x - RADIUS, this.pos.y, this.pos.z - RADIUS),
      new THREE.Vector3(this.pos.x + RADIUS, this.pos.y + this.height, this.pos.z + RADIUS),
    );
    for (const c of this.game.world.colliders) {
      if (!box.intersectsBox(c)) continue;
      if (axis === 'y') {
        if (d < 0) { this.pos.y = c.max.y; this.onGround = true; } else this.pos.y = c.min.y - this.height;
        this.vel.y = 0;
      } else {
        this.pos[axis] = d > 0 ? c.min[axis] - RADIUS - 1e-4 : c.max[axis] + RADIUS + 1e-4;
        this.vel[axis] = 0;
      }
      box.min.set(this.pos.x - RADIUS, this.pos.y, this.pos.z - RADIUS);
      box.max.set(this.pos.x + RADIUS, this.pos.y + this.height, this.pos.z + RADIUS);
    }
  }

  damage(amount) {
    this.health = Math.max(0, this.health - amount);
    this.game.hud?.onDamage?.(amount);
  }
}
