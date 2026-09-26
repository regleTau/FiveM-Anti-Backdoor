// Level geometry and collision. Colliders are axis-aligned boxes
// (THREE.Box3) in `this.colliders`; everything that should block
// movement or bullets registers here. `raycast` covers bullets/AI sight.
import * as THREE from 'three';

export class World {
  constructor(game) {
    this.game = game;
    this.colliders = [];     // THREE.Box3[]
    this.hitMeshes = [];     // meshes bullets can hit (for decals/impacts)
    this.spawnPoints = [];   // THREE.Vector3[] enemy spawns
    this.playerSpawn = new THREE.Vector3(0, 0, 20);
    this.raycaster = new THREE.Raycaster();
  }

  init() {
    const scene = this.game.scene;
    const ground = new THREE.Mesh(
      new THREE.PlaneGeometry(400, 400),
      new THREE.MeshStandardMaterial({ color: 0x6b6358, roughness: 0.95 }),
    );
    ground.rotation.x = -Math.PI / 2;
    ground.receiveShadow = true;
    scene.add(ground);
    this.hitMeshes.push(ground);

    const wallMat = new THREE.MeshStandardMaterial({ color: 0x9a948a, roughness: 0.85 });
    const boxes = [
      [0, -10, 12, 6, 2], [-15, 0, 2, 5, 18], [15, 5, 2, 4, 14], [5, 15, 8, 3, 2], [-6, 8, 3, 1.1, 3],
    ];
    for (const [x, z, w, h, d] of boxes) this.addBox(x, z, w, h, d, wallMat);

    this.spawnPoints.push(new THREE.Vector3(0, 0, -30), new THREE.Vector3(-20, 0, -20), new THREE.Vector3(20, 0, -25));
  }

  addBox(x, z, w, h, d, mat, y = 0) {
    const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), mat);
    m.position.set(x, y + h / 2, z);
    m.castShadow = m.receiveShadow = true;
    this.game.scene.add(m);
    this.hitMeshes.push(m);
    this.colliders.push(new THREE.Box3().setFromObject(m));
    return m;
  }

  // Returns the first intersection against level geometry, or null.
  raycast(origin, dir, far = 500) {
    this.raycaster.set(origin, dir);
    this.raycaster.far = far;
    return this.raycaster.intersectObjects(this.hitMeshes, false)[0] || null;
  }
}
