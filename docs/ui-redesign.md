# VaultSign UI Redesign Spec

**Date:** 2026-04-07
**Status:** Planned
**Theme:** Compact power-user look + animated session visuals
**Color palette:** Adwaita base with neon accents for security elements

---

## 1. Main Window - Compact Power-User Look

### 1.1 Inline Session Progress Bar
- Add a mini `Gtk.ProgressBar` or `Gtk.LevelBar` directly into the session `Adw.ActionRow`
- Shows certificate TTL fraction at a glance without opening session page
- Color: green (>2h), neon orange (<2h), neon red (<30min)
- **File:** `vaultsign_gui.py` (session_row construction, ~line 160)

### 1.2 Compact Layout
- Reduce vertical spacing between groups (`spacing=8` instead of `12`)
- Reduce margins (`margin=8` instead of `12`)
- Tighter padding inside preference groups
- **File:** `vaultsign_gui.py` (main_box construction, ~line 150)

### 1.3 Keyboard-First UX
- Show shortcut hints in button tooltips (e.g. "Authenticate (Ctrl+Enter)")
- Show shortcut hints in menu items where applicable
- **File:** `vaultsign_gui.py` (`_setup_shortcuts`, button construction)

---

## 2. Session Page - Animated Ring Enhancements

### 2.1 Neon Glow Effect
- Add outer glow/halo around the countdown ring arc
- Use Cairo `set_source_rgba` with low-alpha wide stroke behind the main arc
- Color matches ring state: neon green (>2h), neon orange (<2h), neon red (<30min)
- Glow radius: main arc line_width + 12px, alpha 0.15
- **File:** `vaultsign_gui.py` (`_draw_ring` function, ~line 1110)

### 2.2 Pulse Animation on Expiry Warning
- When cert remaining < 30 min (900s), ring glow pulsates
- Use `math.sin(time.time() * 3.0)` for ~0.5 Hz oscillation
- Modulate glow alpha between 0.05 and 0.25
- Also modulate arc alpha between 0.6 and 1.0
- **File:** `vaultsign_gui.py` (`_draw_ring` function)

### 2.3 Gradient Arc
- Ring arc transitions from full opacity at the start to slightly lighter at the tip
- Implement via multiple small arc segments with decreasing alpha
- Or use Cairo linear gradient along the arc path
- **File:** `vaultsign_gui.py` (`_draw_ring` function)

### 2.4 Glow Dot at Arc Tip
- Small glowing dot at the end of the arc (current position indicator)
- Filled circle at arc endpoint, radius = line_width * 0.8
- Same color as ring with alpha 0.5
- **File:** `vaultsign_gui.py` (`_draw_ring` function)

### 2.5 Hour Tick Marks
- Small tick marks around the ring perimeter at hour intervals
- Calculate ticks based on total certificate TTL
- Tick style: short lines (5px) radiating outward from ring
- Color: dim gray (alpha 0.2) to not distract from main arc
- **File:** `vaultsign_gui.py` (`_draw_ring` function)

---

## Implementation Order

| Step | Change | Risk | Files |
|------|--------|------|-------|
| 1 | Compact layout (1.2) | Low | vaultsign_gui.py |
| 2 | Keyboard tooltips (1.3) | Low | vaultsign_gui.py |
| 3 | Neon glow effect (2.1) | Low | vaultsign_gui.py |
| 4 | Pulse animation (2.2) | Low | vaultsign_gui.py |
| 5 | Glow dot at tip (2.4) | Low | vaultsign_gui.py |
| 6 | Hour tick marks (2.5) | Low | vaultsign_gui.py |
| 7 | Gradient arc (2.3) | Medium | vaultsign_gui.py |
| 8 | Inline progress bar (1.1) | Medium | vaultsign_gui.py |

**Approach:** Implement one step at a time, test after each, proceed only if working.

---

## Color Reference

| State | Adwaita | Neon accent (ring/glow) |
|-------|---------|------------------------|
| OK (>2h) | default | `rgba(0.2, 0.9, 0.4, 1.0)` - neon green |
| Warning (<2h) | warning | `rgba(1.0, 0.75, 0.1, 1.0)` - neon orange |
| Critical (<30min) | error | `rgba(1.0, 0.2, 0.2, 1.0)` - neon red |
| Expired | error | `rgba(0.5, 0.1, 0.1, 1.0)` - dim red |

## Notes

- All changes are in `vaultsign_gui.py` only (no backend changes)
- Cairo drawing changes are isolated to `_draw_ring()` function
- No custom CSS providers (caused rendering issues on Fedora 43 with GTK 4.20)
- Test on dark theme (prefer-dark) as primary target
