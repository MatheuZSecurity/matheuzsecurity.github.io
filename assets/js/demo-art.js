(() => {
    const canvas = document.querySelector('.demo-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const fallback = document.querySelector('.demo-art .logo-art');
    const button = document.querySelector('.demo-toggle:not(.demo-music)');
    const lines = fallback.textContent.trimEnd().split('\n');
    while (lines.length && !lines[0].trim()) lines.shift();
    const motion = matchMedia('(prefers-reduced-motion: reduce)');
    const W = 720, H = 260;
    ctx.scale(2, 2);
    const stars = Array.from({ length: 65 }, (_, i) => ({
        x: (i * 137.51) % W, y: (i * 73.37) % 188,
        speed: 3 + i % 8, size: i % 5 === 0 ? 1.5 : 0.7
    }));
    let paused = motion.matches, visible = true, frame = 0, previous = 0, time = 0;

    function wireframe(cx, cy, t, direction) {
        const vertices = [[0,-25,0],[25,0,0],[0,0,25],[-25,0,0],[0,0,-25],[0,25,0]];
        const points = vertices.map(([x,y,z]) => {
            const a = t * direction, b = 0.45;
            const rx = x * Math.cos(a) - z * Math.sin(a);
            const rz = x * Math.sin(a) + z * Math.cos(a);
            return [cx + rx, cy + y * Math.cos(b) - rz * Math.sin(b)];
        });
        ctx.strokeStyle = '#28774a'; ctx.lineWidth = 0.7;
        ctx.beginPath();
        for (const [a,b] of [[0,1],[0,2],[0,3],[0,4],[5,1],[5,2],[5,3],[5,4],[1,2],[2,3],[3,4],[4,1]]) {
            ctx.moveTo(...points[a]); ctx.lineTo(...points[b]);
        }
        ctx.stroke();
    }

    function draw(t) {
        ctx.fillStyle = '#000'; ctx.fillRect(0, 0, W, H);
        for (const star of stars) {
            const x = ((star.x - t * star.speed) % W + W) % W;
            ctx.fillStyle = star.size > 1 ? '#87ae96' : '#355441';
            ctx.fillRect(x, star.y, star.size, star.size);
        }
        // Perspective grid travelling toward the viewer.
        const horizon = 157;
        ctx.lineWidth = 0.65;
        const grid = ctx.createLinearGradient(0, horizon, 0, H);
        grid.addColorStop(0, '#082e18'); grid.addColorStop(1, '#247840');
        ctx.strokeStyle = grid; ctx.beginPath();
        for (let i = -12; i <= 12; i++) {
            ctx.moveTo(W / 2 + i * 12, horizon);
            ctx.lineTo(W / 2 + i * 110, H);
        }
        for (let i = 0; i < 13; i++) {
            const depth = ((i / 13 + t * 0.055) % 1);
            const y = horizon + depth * depth * (H - horizon);
            ctx.moveTo(0, y); ctx.lineTo(W, y);
        }
        ctx.stroke();
        wireframe(64, 137, t * 0.65, 1);
        wireframe(656, 137, t * 0.65, -1);

        // Draw the actual ASCII lettering, with a travelling copper-style highlight.
        const size = 13.2, lineHeight = 13;
        ctx.font = `${size}px monospace`;
        ctx.textBaseline = 'top';
        const width = Math.max(...lines.map(line => ctx.measureText(line).width));
        const left = (W - width) / 2;
        const top = 42 + Math.sin(t * 0.8) * 5;
        const gradient = ctx.createLinearGradient(0, top, 0, top + lines.length * lineHeight);
        gradient.addColorStop(0, '#e2ffe8'); gradient.addColorStop(0.25, '#82f8a2');
        gradient.addColorStop(0.48, '#2bb85c'); gradient.addColorStop(0.52, '#b5ffcd');
        gradient.addColorStop(0.72, '#46e06a'); gradient.addColorStop(1, '#14542b');
        lines.forEach((line, row) => {
            const wave = Math.sin(t * 1.3 + row * 0.38) * 3;
            ctx.fillStyle = '#0a321b';
            ctx.fillText(line, left + wave + 3, top + row * lineHeight + 4);
            ctx.fillStyle = gradient;
            ctx.shadowColor = '#36d66a'; ctx.shadowBlur = 5;
            ctx.fillText(line, left + wave, top + row * lineHeight);
            ctx.shadowBlur = 0;
        });
        ctx.fillStyle = '#598c68'; ctx.font = '9px monospace';
        ctx.textAlign = 'center'; ctx.fillText('*  UNDERGROUND RESEARCH / 0xMATHEUZ  *', W / 2, 17);
        ctx.textAlign = 'left';

        // Sine scroller, a familiar cracktro signature.
        const message = 'LINUX INTERNALS   /   OFFENSIVE SECURITY   /   HACK THE PLANET   /   ';
        ctx.font = 'bold 12px monospace';
        const advance = ctx.measureText('M').width, span = message.length * advance;
        const offset = (t * 32) % span;
        for (let repeat = 0; repeat < Math.ceil(W / span) + 1; repeat++) {
            for (let i = 0; i < message.length; i++) {
                const x = repeat * span + i * advance - offset;
                const y = 199 + Math.sin(x / 75 + t * 1.6) * 7;
                ctx.fillStyle = '#96cda6'; ctx.fillText(message[i], x, y);
            }
        }
        ctx.fillStyle = '#00000028';
        for (let y = 0; y < H; y += 3) ctx.fillRect(0, y, W, 1);
    }

    function tick(now) {
        frame = 0;
        if (paused || !visible || document.hidden) return;
        if (previous) time += Math.min((now - previous) / 1000, 0.05);
        previous = now;
        draw(time);
        frame = requestAnimationFrame(tick);
    }
    function sync() {
        cancelAnimationFrame(frame); previous = 0;
        button.textContent = paused ? 'play animation' : 'pause animation';
        button.setAttribute('aria-pressed', String(paused));
        if (!paused && visible && !document.hidden) frame = requestAnimationFrame(tick);
    }
    button.addEventListener('click', () => { paused = !paused; sync(); });
    motion.addEventListener('change', () => { paused = motion.matches; sync(); });
    document.addEventListener('visibilitychange', sync);
    if ('IntersectionObserver' in window) {
        new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; sync(); }).observe(canvas);
    }
    draw(0);
    fallback.hidden = true; canvas.hidden = false; button.hidden = false;
    sync();
})();
