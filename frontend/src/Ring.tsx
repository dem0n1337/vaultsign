type RingProps = {
  fraction: number // 0..1 remaining
  label: string
  caption: string
  state: 'ok' | 'warn' | 'danger' | 'idle'
}

const COLORS = {
  ok: ['#34d17a', '#23b3ff'],
  warn: ['#ffbe1a', '#ff8a3c'],
  danger: ['#ff5a5a', '#ff2d6f'],
  idle: ['#3a3a52', '#3a3a52'],
} as const

export default function Ring({ fraction, label, caption, state }: RingProps) {
  const size = 200
  const stroke = 14
  const r = (size - stroke) / 2
  const circ = 2 * Math.PI * r
  const dash = Math.max(0, Math.min(1, fraction)) * circ
  const [c1, c2] = COLORS[state]
  const pulsing = state === 'danger'

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <defs>
          <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={c1} />
            <stop offset="100%" stopColor={c2} />
          </linearGradient>
          <filter id="ringGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#23233322" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#ffffff10" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="url(#ringGrad)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          filter="url(#ringGlow)"
          className={pulsing ? 'pulse-ring' : ''}
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-4xl font-semibold tracking-tight">{label}</div>
        <div className="text-xs uppercase tracking-widest text-white/40 mt-1">{caption}</div>
      </div>
    </div>
  )
}
