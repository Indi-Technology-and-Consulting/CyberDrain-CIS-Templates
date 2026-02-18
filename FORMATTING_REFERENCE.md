# Spreadsheet Formatting Reference

Script: `format_spreadsheet.py`
Dependency: `openpyxl` — install with `python -m pip install openpyxl`
Run from the `Summary CSV/` directory: `python format_spreadsheet.py`

---

## Colour Palette

| Element | Hex | Preview |
|---|---|---|
| Header background | `#1F3864` | Dark navy |
| Header text | `#FFFFFF` | White |
| Even row background | `#EEF3FA` | Light blue-grey |
| Odd row background | `#FFFFFF` | White |
| Cell border | `#BFC9D6` | Muted blue-grey |

### Complexity Badge Colours

| Value | Background | Text |
|---|---|---|
| Simple | `#C6EFCE` | `#276221` (dark green) |
| Moderate | `#FFEB9C` | `#9C6500` (dark amber) |
| Complex | `#FFC7CE` | `#9C0006` (dark red) |

---

## Column Configuration

| # | Column | Width (chars) |
|---|---|---|
| 1 | Name | 55 |
| 2 | Description | 70 |
| 3 | Recommended Setting | 40 |
| 4 | Complexity | 13 |
| 5 | SMB Justification | 65 |

---

## Spreadsheet Features

- **Frozen header row** — row 1 stays visible while scrolling (`freeze_panes = "A2"`)
- **Auto-filter** — dropdown on every header cell
- **Alternating row shading** — even/odd rows use different backgrounds
- **Text wrap** — enabled on all cells; vertical alignment is `top`
- **Row heights** — header: 28pt, data rows: 60pt
- **Font** — Segoe UI, 10pt headers / 9pt data
- **Thin border** — all four sides on every cell
- **Sheet tab colour** — matches header navy (`#1F3864`)

---

## Input File Requirements

- UTF-8 with or without BOM (`utf-8-sig` handles both)
- First row is treated as headers
- Column 4 (zero-indexed: 3) must contain the Complexity value for badge colouring
- Short rows are padded with empty strings automatically

### Control Character Handling

openpyxl rejects XML control characters (U+0000–U+0008, U+000B, U+000C, U+000E–U+001F).
The `clean()` function strips these silently before writing each cell value.
Printable characters, newlines (`\n`), and tabs (`\t`) are preserved.

---

## Adding a New Complexity Level

Edit the `COMPLEXITY` dict in `format_spreadsheet.py`:

```python
COMPLEXITY = {
    "Simple":   ("C6EFCE", "276221"),
    "Moderate": ("FFEB9C", "9C6500"),
    "Complex":  ("FFC7CE", "9C0006"),
    "NewLevel": ("BACKGROUND_HEX", "TEXT_HEX"),   # add here
}
```

## Adapting for a Different CSV

1. Update `INPUT_CSV` and `OUTPUT_XLS` at the top of the script.
2. Adjust `COL_WIDTHS` to match the new column count and content widths.
3. If the colour-coded column moves, update the `col_idx == 4` check and the `COMPLEXITY` key strings.
4. Change `ws.title` to an appropriate sheet name.
