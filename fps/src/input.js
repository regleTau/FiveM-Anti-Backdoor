// Keyboard/mouse state with pointer lock.
export class Input {
  constructor(game) {
    this.game = game;
    this.keys = new Set();
    this.mouse = { dx: 0, dy: 0, left: false, right: false };
    this.pressed = new Set(); // keys pressed this frame
  }

  init() {
    const menu = document.getElementById('menu');
    const canvas = this.game.canvas;
    const lock = () => canvas.requestPointerLock?.();
    menu.addEventListener('click', lock);
    canvas.addEventListener('click', lock);
    document.addEventListener('pointerlockchange', () => {
      const locked = document.pointerLockElement === canvas;
      this.game.paused = !locked;
      menu.style.display = locked ? 'none' : '';
      if (locked) this.game.audio?.resume();
    });
    addEventListener('keydown', (e) => {
      if (!this.keys.has(e.code)) this.pressed.add(e.code);
      this.keys.add(e.code);
      if (e.code === 'Space' || e.code.startsWith('Control')) e.preventDefault();
    });
    addEventListener('keyup', (e) => this.keys.delete(e.code));
    addEventListener('mousemove', (e) => {
      if (document.pointerLockElement !== canvas) return;
      this.mouse.dx += e.movementX;
      this.mouse.dy += e.movementY;
    });
    addEventListener('mousedown', (e) => {
      if (e.button === 0) this.mouse.left = true;
      if (e.button === 2) this.mouse.right = true;
    });
    addEventListener('mouseup', (e) => {
      if (e.button === 0) this.mouse.left = false;
      if (e.button === 2) this.mouse.right = false;
    });
    addEventListener('contextmenu', (e) => e.preventDefault());
  }

  down(code) { return this.keys.has(code); }
  wasPressed(code) { return this.pressed.has(code); }

  // Called last in the frame by ShotMode's update ordering; consumers read
  // deltas during their update, then we clear.
  consumeMouse() {
    const d = { dx: this.mouse.dx, dy: this.mouse.dy };
    this.mouse.dx = this.mouse.dy = 0;
    return d;
  }

  endFrame() { this.pressed.clear(); }
}
