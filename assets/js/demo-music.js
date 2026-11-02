// Original cracktro-flavoured chiptune, synthesized locally; no audio downloads.
// A tiny JS tracker renders the whole tune once (soft PWM lead, tracker echo,
// 50 Hz arps in the chorus, triangle bass, noise drums, wide Amiga-ish stereo)
// at 22 kHz with light bit reduction, then loops it seamlessly.
(() => {
    const button = document.querySelector('.demo-music');
    const AudioEngine = window.AudioContext || window.webkitAudioContext;
    if (!button || !AudioEngine) return;

    const BPM = 124, STEP = 60 / BPM / 4, BAR = 16, RATE = 22050;
    const TAU = Math.PI * 2;
    const hz = n => 440 * 2 ** ((n - 69) / 12);

    const C = {
        Am: { root: 45, tones: [57, 60, 64] }, F: { root: 41, tones: [53, 57, 60] },
        C: { root: 48, tones: [55, 60, 64] }, G: { root: 43, tones: [55, 59, 62] },
        Dm: { root: 38, tones: [53, 57, 62] }, E: { root: 40, tones: [56, 59, 64] }
    };

    // number = note on, "." = hold, "-" = rest
    const VERSE = parse(`
        76 . . . . . 72 . 74 . 76 . . . . .
        77 . . . 76 . 74 . 72 . . . . . . .
        72 . . . 76 . 79 . 76 . . . 74 . 72 .
        74 . . . . . . . - . 71 . 72 . 74 .
        76 . . . . . 72 . 74 . 76 . . . 81 .
        81 . . . 79 . 77 . 76 . . . 77 . 76 .
        74 . . . 77 . 76 . 74 . 72 . 74 . . .
        71 . . . . . . . 68 . 71 . 74 . 76 .`);
    const CHORUS = parse(`
        81 . . 79 . . 77 . 79 . . 81 . . 84 .
        83 . . 81 . . 79 . 74 . . . . . . .
        76 . . 79 . . 81 . 84 . . 83 . . 81 .
        81 . . . . . . . 79 . 76 . 79 . . .
        81 . . 79 . . 77 . 79 . . 81 . . 84 .
        86 . . 84 . . 83 . 79 . . . 81 . 83 .
        80 . . . . . . . 83 . . . 80 . . .
        76 . . . . . . . . . . . - . . .`);
    const BREAK = parse(`
        77 . . . . . . . 76 . . . 74 . . .
        72 . . . . . . . . . . . . . . .
        72 . . . 74 . . . 76 . . . 77 . . .
        76 . . . . . . . 74 . . . 71 . . .`);

    const SONG = [
        { kind: 'intro', chords: ['Am', 'F', 'C', 'G'] },
        { kind: 'verse', chords: ['Am', 'F', 'C', 'G', 'Am', 'F', 'Dm', 'E'], lead: VERSE },
        { kind: 'chorus', chords: ['F', 'G', 'Am', 'Am', 'F', 'G', 'E', 'E'], lead: CHORUS },
        { kind: 'break', chords: ['Dm', 'Am', 'F', 'E'], lead: BREAK },
        { kind: 'chorus', chords: ['F', 'G', 'Am', 'Am', 'F', 'G', 'E', 'E'], lead: CHORUS, double: true }
    ];
    const LOOP_FROM = 1; // skip the intro when looping

    let live, source, playing = false;

    function parse(text) {
        const tokens = text.trim().split(/\s+/), events = new Array(tokens.length);
        tokens.forEach((t, i) => {
            if (t === '.' || t === '-') return;
            let len = 1;
            while (tokens[i + len] === '.') len++;
            events[i] = [Number(t), len];
        });
        return events;
    }

    function render(ctx) {
        const starts = [];
        let total = 0;
        for (const s of SONG) { starts.push(total); total += s.chords.length * BAR; }
        const loopStart = starts[LOOP_FROM] * STEP, loopEnd = total * STEP;
        const length = Math.ceil((loopEnd + 2) * RATE);
        const L = new Float32Array(length), R = new Float32Array(length);

        function voice(at, seconds, pan, fn) {
            const s0 = Math.round(at * RATE), n = Math.min(Math.round(seconds * RATE), length - s0);
            const gl = Math.min(1, 1 - pan), gr = Math.min(1, 1 + pan);
            for (let i = 0; i < n; i++) {
                const v = fn(i / RATE, i);
                L[s0 + i] += v * gl; R[s0 + i] += v * gr;
            }
        }
        // attack / hold / release envelope
        const ahr = (t, attack, hold, release) =>
            t < attack ? t / attack : t < hold ? 1 : Math.max(0, 1 - (t - hold) / release);

        // Soft PWM pulse lead, gently low-passed, with delayed vibrato and portamento.
        function lead(note, at, steps, pan, vol, slideFrom, soft) {
            const hold = steps * STEP - 0.02, f0 = hz(note), fs = slideFrom ? hz(slideFrom) : f0;
            const a = 1 - Math.exp(-TAU * (soft ? 1600 : 3200) / RATE);
            let phase = 0, y = 0;
            voice(at, hold + 0.15, pan, t => {
                let f = t < 0.04 && fs !== f0 ? fs * (f0 / fs) ** (t / 0.04) : f0;
                if (hold > 0.3 && t > 0.18) f *= 1 + 0.007 * Math.min(1, (t - 0.18) / 0.15) * Math.sin(TAU * 5.5 * t);
                phase = (phase + f / RATE) % 1;
                const duty = soft ? 0.5 : 0.36 + 0.12 * Math.sin(TAU * 0.9 * t);
                y += a * ((phase < duty ? 1 : -1) - (2 * duty - 1) - y);
                const decay = t < hold ? 1 - 0.3 * Math.min(1, t / 0.25) : 0.7;
                return y * ahr(t, 0.008, hold, 0.15) * decay * vol;
            });
        }

        // Plucky single note (broken chords in verse / intro).
        function pluck(note, at, vol, pan) {
            const f = hz(note), a = 1 - Math.exp(-TAU * 2200 / RATE);
            let phase = 0, y = 0;
            voice(at, 0.35, pan, t => {
                phase = (phase + f / RATE) % 1;
                y += a * ((phase < 0.25 ? 1.5 : -0.5) - y);
                return y * vol * Math.exp(-9 * t);
            });
        }

        // Tracker 0xy arpeggio: one pulse voice cycling chord tones at 50 Hz.
        function arp(tones, at, seconds, octave, vol) {
            const inc = tones.map(n => hz(n + octave) / RATE), a = 1 - Math.exp(-TAU * 2600 / RATE);
            let phase = 0, y = 0;
            voice(at, seconds, 0.55, t => {
                phase = (phase + inc[Math.floor(t * 50) % 3]) % 1;
                y += a * ((phase < 0.25 ? 1.5 : -0.5) - y);
                return y * vol * Math.exp(-3.5 * t) * ahr(t, 0.003, seconds - 0.02, 0.02);
            });
        }

        // NES-style triangle bass.
        function bass(note, at, seconds) {
            const f = hz(note);
            let phase = 0;
            voice(at, seconds, 0.1, t => {
                phase = (phase + f / RATE) % 1;
                const tri = phase < 0.5 ? 4 * phase - 1 : 3 - 4 * phase;
                return Math.round(tri * 7.5) / 7.5 * 0.32 * ahr(t, 0.004, seconds - 0.03, 0.03);
            });
        }

        function noise(at, seconds, cutoff, vol, pan) {
            const a = Math.exp(-TAU * cutoff / RATE);
            let x = 0, prev = 0, hp = 0;
            voice(at, seconds, pan, (t, i) => {
                if (i % 2 === 0) x = Math.random() * 2 - 1;
                hp = a * (hp + x - prev); prev = x;
                return hp * vol * Math.exp(-5 * t / seconds);
            });
        }
        function drop(at, from, to, seconds, vol) {
            let phase = 0;
            voice(at, seconds, 0, t => {
                phase = (phase + from * (to / from) ** (t / seconds) / RATE) % 1;
                return Math.sin(TAU * phase) * vol * Math.exp(-4.6 * t / seconds);
            });
        }
        const kick = at => drop(at, 170, 45, 0.22, 0.8);
        const snare = (at, v) => { noise(at, 0.16, 900, 0.32 * v, -0.15); drop(at, 220, 160, 0.05, 0.18 * v); };
        const hat = (at, v, open) => noise(at, open ? 0.12 : 0.03, 7000, v, 0.3);

        let lastLead = 0;
        SONG.forEach((sec, si) => {
            const bars = sec.chords.length;
            for (let local = 0; local < bars * BAR; local++) {
                const at = (starts[si] + local) * STEP, bar = Math.floor(local / BAR), pos = local % BAR;
                const ch = C[sec.chords[bar]], lastBar = bar === bars - 1;
                const broken = [0, 1, 2, 1], beat = pos >> 2;

                if (sec.kind === 'intro') {
                    if (pos % 2 === 0) pluck(ch.tones[broken[(pos >> 1) % 4]] + 12, at, 0.08, 0.5);
                    if (pos === 0) bass(ch.root, at, BAR * STEP * 0.95);
                    if (lastBar && pos >= 8 && pos % 2 === 0) hat(at, 0.05 + pos * 0.006, false);
                }
                if (sec.kind === 'verse') {
                    if (pos % 2 === 0) pluck(ch.tones[broken[(pos >> 1) % 4]] + (beat % 2 ? 12 : 0), at, 0.07, 0.55);
                    if (pos % 4 === 0 || pos === 6 || pos === 14) bass(ch.root + (pos === 6 || pos === 14 ? 12 : 0), at, STEP * 1.6);
                    if (pos === 0 || pos === 8 || pos === 11) kick(at);
                    if (pos === 4 || pos === 12) snare(at, 0.8);
                    if (pos % 2 === 0) hat(at, pos % 4 ? 0.07 : 0.04, false);
                }
                if (sec.kind === 'chorus') {
                    if (pos % 2 === 0) arp(ch.tones, at, STEP * 1.8, beat % 2 ? 12 : 0, 0.07);
                    if (pos % 2 === 0) bass(ch.root + (pos % 4 ? 12 : 0), at, STEP * 1.7);
                    if (pos === 0 || pos === 6 || pos === 8 || pos === 10) kick(at);
                    if (pos === 4 || pos === 12) snare(at, 1);
                    if (pos % 4 === 2) hat(at, 0.09, true);
                    else if (pos % 2 === 0) hat(at, 0.05, false);
                    if (sec.double && lastBar && pos >= 12) snare(at, 0.35 + (pos - 12) * 0.1);
                }
                if (sec.kind === 'break') {
                    if (pos === 0) bass(ch.root, at, BAR * STEP * 0.97);
                    if (pos % 4 === 0) arp(ch.tones, at, STEP * 3.6, 12, 0.045);
                    if (lastBar && pos >= 8) snare(at, 0.25 + (pos - 8) * 0.07);
                }

                const ev = sec.lead && sec.lead[local];
                if (ev) {
                    const [note, len] = ev, soft = sec.kind === 'break';
                    const slide = lastLead && Math.abs(lastLead - note) <= 4 ? lastLead : 0;
                    lead(note, at, len, -0.45, soft ? 0.07 : 0.085, slide, soft);
                    lead(note, at + STEP * 3, len, 0.6, 0.025, 0, true);      // tracker echo
                    if (sec.double) lead(note - 12, at, len, 0.2, 0.04, slide && slide - 12, true);
                    lastLead = note;
                }
            }
        });

        // Fold the tail past the loop end onto the loop start, normalise and
        // reduce to ~10 bits for a little grit.
        const a = Math.round(loopStart * RATE), b = Math.round(loopEnd * RATE);
        let peak = 0;
        for (const d of [L, R]) {
            for (let i = b; i < length; i++) d[a + i - b] += d[i];
            for (let i = 0; i < b; i++) peak = Math.max(peak, Math.abs(d[i]));
        }
        const scale = 0.9 / (peak || 1);
        const buffer = ctx.createBuffer(2, b, RATE);
        [L, R].forEach((d, k) => {
            const out = buffer.getChannelData(k);
            for (let i = 0; i < b; i++) out[i] = Math.round(d[i] * scale * 511) / 511;
        });
        return { buffer, loopStart, loopEnd };
    }

    async function start() {
        if (!live) live = new AudioEngine();
        await live.resume();
        if (!source) {
            button.textContent = 'music: loading';
            await new Promise(r => setTimeout(r, 30)); // let the label paint
            const { buffer, loopStart, loopEnd } = render(live);
            const smooth = live.createBiquadFilter(), out = live.createGain();
            smooth.type = 'lowpass'; smooth.frequency.value = 8000;
            out.gain.value = 0.4;
            source = live.createBufferSource();
            source.buffer = buffer; source.loop = true;
            source.loopStart = loopStart; source.loopEnd = loopEnd;
            source.connect(smooth).connect(out).connect(live.destination);
            source.start();
        }
    }

    async function stop() {
        playing = false;
        button.textContent = 'music: off';
        button.setAttribute('aria-pressed', 'false');
        if (live) await live.suspend();
    }

    button.addEventListener('click', async () => {
        button.disabled = true;
        try {
            if (playing) await stop();
            else {
                await start();
                playing = true;
                button.textContent = 'music: on';
                button.setAttribute('aria-pressed', 'true');
            }
        } catch {
            await stop().catch(() => {});
            button.textContent = 'music: retry';
        } finally {
            button.disabled = false;
        }
    });
    document.addEventListener('visibilitychange', () => {
        if (document.hidden && playing) stop().catch(() => {});
    });
    button.hidden = false;
})();
