// DOM HUD: crosshair, ammo, health/damage vignette, hitmarkers, killfeed.
export class Hud {
  constructor(game) {
    this.game = game;
    this.kills = 0;
  }

  init() {
    const root = document.getElementById('hud');
    root.innerHTML = `
      <div class="crosshair"></div>
      <div class="hitmarker"></div>
      <div class="ammo"><span class="mag">30</span> / <span class="reserve">120</span></div>
      <div class="health"><div class="bar"></div></div>
      <div class="damage"></div>`;
    this.el = {
      crosshair: root.querySelector('.crosshair'),
      hit: root.querySelector('.hitmarker'),
      mag: root.querySelector('.mag'),
      reserve: root.querySelector('.reserve'),
      bar: root.querySelector('.health .bar'),
      damage: root.querySelector('.damage'),
    };
    this.hitT = 0;
    this.dmgT = 0;
  }

  hitmarker() { this.hitT = 0.15; }
  onDamage() { this.dmgT = 0.6; }
  onKill() { this.kills++; }

  update(dt) {
    const w = this.game.weapons;
    this.el.mag.textContent = w.ammo;
    this.el.reserve.textContent = w.reserve;
    this.el.bar.style.width = `${this.game.player.health}%`;
    this.el.crosshair.style.opacity = 1 - w.adsFactor;
    this.hitT -= dt;
    this.dmgT -= dt;
    this.el.hit.style.opacity = this.hitT > 0 ? 1 : 0;
    this.el.damage.style.opacity = Math.max(0, this.dmgT);
  }
}
