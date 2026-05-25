import { useEffect, useRef, useState } from 'react'

type Props = {
  value: string
  options: string[]
  onChange: (v: string) => void
}

// Dropdown is a fully theme-styled replacement for the native <select>, which
// renders with the OS's (light) chrome and broke the dark theme.
export default function Dropdown({ value, options, onChange }: Props) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  return (
    <div ref={ref} className="relative flex-1">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between bg-card-hi border border-border rounded-lg px-3 py-2 outline-none focus:border-accent transition t-fg"
      >
        <span className="truncate">{value}</span>
        <span className={'t-faint ml-2 transition-transform ' + (open ? 'rotate-180' : '')}>▾</span>
      </button>
      {open && (
        <div className="absolute z-20 mt-1 w-full rounded-lg bg-card border border-border shadow-xl shadow-black/40 overflow-hidden fade-up">
          {options.map((o) => (
            <button
              key={o}
              onClick={() => { onChange(o); setOpen(false) }}
              className={'w-full text-left px-3 py-2 transition hover:bg-accent/15 ' + (o === value ? 'text-accent' : 't-muted')}
            >
              {o}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
