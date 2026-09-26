// Procedural audio via Web Audio (no external sound files).
export class Audio {
  constructor(game) {
    this.game = game;
    this.ctx = null;
  }

  resume() {
    if (!this.ctx) this.ctx = new AudioContext();
    this.ctx.resume();
  }

  play(name) {
    if (!this.ctx) return;
    const ctx = this.ctx;
    const len = 0.15;
    const buf = ctx.createBuffer(1, ctx.sampleRate * len, ctx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < d.length; i++) d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / d.length, 4);
    const src = ctx.createBufferSource();
    src.buffer = buf;
    const g = ctx.createGain();
    g.gain.value = 0.4;
    src.connect(g).connect(ctx.destination);
    src.start();
  }
}
