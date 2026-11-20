"""RDP bitmap cache image reconstruction.

bmc-tools only extracts the cache tiles (64x64 pieces of the remote screen). This module rebuilds
screen fragments from them, like a jigsaw solver:
  1. dissimilarity of every tile border against every other (border pixels + linear prediction
     from the next pixel row/column inward), as matrix products
  2. joins = mutual best matches that clearly beat the runner-up (ratio test); flat/uniform borders
     are ambiguous and never used as joins
  3. greedy assembly on a grid, strongest joins first, rejecting overlaps and merges whose other
     new contacts do not fit
  4. holes surrounded by >= 3 placed tiles are filled with the best fitting unplaced/uniform tile
Every fragment is traceable: <cache>_fragments.csv maps each grid cell to its bmc-tools tile file.
"""
from __future__ import annotations

import csv
import hashlib
import html
import os
import re
from pathlib import Path
from typing import Callable

os.environ.setdefault("OPENBLAS_NUM_THREADS", "4")  # BLAS: leave cores for the tools running in parallel
os.environ.setdefault("OMP_NUM_THREADS", "4")

try:
    import numpy as np
    from PIL import Image
except ImportError:  # installed by setup.sh (requirements.txt)
    np = Image = None

TILE = 64
TILE_RX = re.compile(r"_(\d{4,})\.bmp$", re.I)  # bmc-tools: <cache>_<index>.bmp (also _old_<index>, skipped)
BG = (38, 38, 38)                               # empty grid cells


def available() -> bool:
    return np is not None


# =============================================================================== tiles
def load_tiles(d: Path) -> tuple[list[str], "np.ndarray"]:
    names, arrs = [], []
    for p in sorted(d.iterdir()):
        if not TILE_RX.search(p.name) or "_old_" in p.name:
            continue
        try:
            with Image.open(p) as im:
                a = np.asarray(im.convert("RGB"))
        except OSError:
            continue
        if a.shape[:2] == (TILE, TILE):  # partial (screen edge) tiles cannot be placed on the grid
            names.append(p.name)
            arrs.append(a)
    return names, (np.stack(arrs) if arrs else np.zeros((0, TILE, TILE, 3), np.uint8))


def _sq_dist(x: "np.ndarray", y: "np.ndarray") -> "np.ndarray":
    """Mean squared difference between every row of x and every row of y."""
    d = (x * x).sum(1)[:, None] + (y * y).sum(1)[None, :] - 2.0 * (x @ y.T)
    np.maximum(d, 0, out=d)
    return d / x.shape[1]


def _borders(t: "np.ndarray", side: str) -> tuple["np.ndarray", "np.ndarray"]:
    """(border pixels, next pixels inward) of every tile, flattened."""
    sl = {"r": (np.s_[:, :, -1], np.s_[:, :, -2]), "l": (np.s_[:, :, 0], np.s_[:, :, 1]),
          "b": (np.s_[:, -1, :], np.s_[:, -2, :]), "t": (np.s_[:, 0, :], np.s_[:, 1, :])}[side]
    n = len(t)
    return t[sl[0]].reshape(n, -1), t[sl[1]].reshape(n, -1)


def dissimilarity(t: "np.ndarray", horizontal: bool) -> "np.ndarray":
    """D[i, j] = mismatch when tile j sits right of (horizontal) / below tile i. Lower = better."""
    a, a_in = _borders(t, "r" if horizontal else "b")
    b, b_in = _borders(t, "l" if horizontal else "t")
    d = _sq_dist(a, b)                                # border pixels against each other
    d += 0.5 * _sq_dist(2 * a - a_in, b)              # i's gradient predicts j's border
    d += 0.5 * _sq_dist(a, 2 * b - b_in)              # and the other way round
    return d.astype(np.float32)


# =============================================================================== solver
class Stitcher:
    def __init__(self, tiles: "np.ndarray", max_mse: float = 150.0, ratio: float = 0.85,
                 flat_std: float = 2.0, progress: Callable[[str], None] | None = None):
        self.t8 = tiles
        self.t = tiles.astype(np.float32)
        self.max_mse, self.ratio, self.flat_std = max_mse, ratio, flat_std
        self.say = progress or (lambda m: None)
        n = len(tiles)
        self.uniform = self.t.reshape(n, -1).std(1) < flat_std
        seen: dict[bytes, int] = {}
        self.dup_of = np.full(n, -1)
        for i in range(n):
            h = hashlib.blake2b(tiles[i].tobytes(), digest_size=16).digest()
            if h in seen:
                self.dup_of[i] = seen[h]
            else:
                seen[h] = i
        # tiles that take part in matching: unique and not a flat colour
        self.active = np.flatnonzero(~self.uniform & (self.dup_of < 0))
        self.D: dict[bool, np.ndarray] = {}
        self.pos: dict[int, tuple[int, int]] = {}      # active-local index -> grid cell
        self.frag: dict[int, int] = {}
        self.cells: dict[int, dict[tuple[int, int], int]] = {}

    # ------------------------------------------------------------ joins
    def _links(self, horizontal: bool) -> list[tuple[float, int, int, int, int]]:
        ta = self.t[self.active]
        D = dissimilarity(ta, horizontal)
        self.D[horizontal] = D
        np.fill_diagonal(D, np.inf)
        a, _ = _borders(ta, "r" if horizontal else "b")
        b, _ = _borders(ta, "l" if horizontal else "t")
        Dm = D.copy()
        Dm[a.std(1) < self.flat_std, :] = np.inf       # flat borders fit everything -> no evidence
        Dm[:, b.std(1) < self.flat_std] = np.inf
        n = len(ta)
        if n < 3:
            return []
        best_r = Dm.argmin(1)
        best_c = Dm.argmin(0)
        two_r = np.partition(Dm, 1, axis=1)[:, :2]
        two_c = np.partition(Dm, 1, axis=0)[:2, :]
        dx, dy = (1, 0) if horizontal else (0, 1)
        out = []
        for i in range(n):
            j = int(best_r[i])
            if best_c[j] != i:                         # not mutual best buddies
                continue
            d = float(Dm[i, j])
            if not np.isfinite(d) or d > self.max_mse:
                continue
            second = min(float(two_r[i, 1]), float(two_c[1, j]))
            r = (d + 1.0) / (second + 1.0)
            if r <= self.ratio:
                out.append((1.0 - r, i, j, dx, dy))
        return out

    def _contact_cost(self, a: int, b: int, horizontal: bool) -> float:
        return float(self.D[horizontal][a, b])

    # ------------------------------------------------------------ assembly
    def _merge(self, a: int, b: int, dx: int, dy: int) -> bool:
        for x in (a, b):
            if x not in self.frag:
                self.frag[x], self.pos[x], self.cells[x] = x, (0, 0), {(0, 0): x}
        fa, fb = self.frag[a], self.frag[b]
        if fa == fb:
            return False
        ox, oy = self.pos[a][0] + dx - self.pos[b][0], self.pos[a][1] + dy - self.pos[b][1]
        big, small = (fa, fb) if len(self.cells[fa]) >= len(self.cells[fb]) else (fb, fa)
        if small == fa:
            ox, oy = -ox, -oy
        cb, cs = self.cells[big], self.cells[small]
        moved = {(x + ox, y + oy): t for (x, y), t in cs.items()}
        if any(c in cb for c in moved):
            return False
        costs = []                                     # every new contact must be plausible too
        for (x, y), t in moved.items():
            for (nx, ny), horiz, first in (((x - 1, y), True, False), ((x + 1, y), True, True),
                                           ((x, y - 1), False, False), ((x, y + 1), False, True)):
                u = cb.get((nx, ny))
                if u is not None:
                    costs.append(self._contact_cost(t, u, horiz) if first else self._contact_cost(u, t, horiz))
        if len(costs) > 1 and float(np.median(costs)) > self.max_mse * 2:
            return False
        for c, t in moved.items():
            cb[c] = t
            self.frag[t], self.pos[t] = big, c
        del self.cells[small]
        return True

    def _fill_holes(self, frags: list[dict[tuple[int, int], int]]) -> dict[int, set]:
        """Fill grid holes with >= 3 placed neighbours using the best fitting free tile (global index)."""
        t = self.t
        used = {int(self.active[i]) for c in frags for i in c.values()}
        free = np.array([i for i in range(len(t)) if i not in used or self.uniform[i]])
        filled: dict[int, set] = {k: set() for k in range(len(frags))}
        if not len(free):
            return filled
        fr = {s: _borders(t[free], s)[0] for s in "lrtb"}
        for k, cells in enumerate(frags):
            g = {c: int(self.active[i]) for c, i in cells.items()}  # cell -> global tile
            for _ in range(3):
                xs, ys = [c[0] for c in g], [c[1] for c in g]
                changed = False
                for x in range(min(xs), max(xs) + 1):
                    for y in range(min(ys), max(ys) + 1):
                        if (x, y) in g:
                            continue
                        cost, cnt = np.zeros(len(free), np.float32), 0
                        for (nx, ny), mine, theirs in (((x - 1, y), "l", np.s_[:, -1]), ((x + 1, y), "r", np.s_[:, 0]),
                                                       ((x, y - 1), "t", np.s_[-1, :]), ((x, y + 1), "b", np.s_[0, :])):
                            u = g.get((nx, ny))
                            if u is None:
                                continue
                            ref = t[u][theirs].reshape(1, -1)
                            cost = np.maximum(cost, ((fr[mine] - ref) ** 2).mean(1))
                            cnt += 1
                        if cnt < 3:
                            continue
                        j = int(cost.argmin())
                        if cost[j] <= self.max_mse:
                            gi = int(free[j])
                            if gi in used and not self.uniform[gi]:
                                continue
                            g[(x, y)] = gi
                            filled[k].add((x, y))
                            if not self.uniform[gi]:
                                used.add(gi)
                                cost_mask = free != gi
                                free, fr = free[cost_mask], {s: v[cost_mask] for s, v in fr.items()}
                            changed = True
                if not changed:
                    break
            frags[k] = g
        return filled

    def solve(self, min_tiles: int = 4) -> list[dict]:
        if len(self.active) < 2:
            return []
        self.say(f"matching {len(self.active)} unique tiles (horizontal)")
        links = self._links(True)
        self.say(f"matching {len(self.active)} unique tiles (vertical)")
        links += self._links(False)
        self.say(f"assembling {len(links)} joins")
        for _, a, b, dx, dy in sorted(links, reverse=True):
            self._merge(a, b, dx, dy)
        frags = sorted((c for c in self.cells.values() if len(c) >= min_tiles), key=len, reverse=True)
        self.say(f"filling holes in {len(frags)} fragments")
        matched = [len(c) for c in frags]
        filled = self._fill_holes(frags)
        out = []
        for k, g in enumerate(frags):
            xs, ys = [c[0] for c in g], [c[1] for c in g]
            x0, y0 = min(xs), min(ys)
            out.append({"cells": {(x - x0, y - y0): i for (x, y), i in g.items()},
                        "filled": {(x - x0, y - y0) for x, y in filled[k]},
                        "cols": max(xs) - x0 + 1, "rows": max(ys) - y0 + 1, "matched": matched[k]})
        return out

    def render(self, frag: dict) -> "Image.Image":
        canvas = np.empty((frag["rows"] * TILE, frag["cols"] * TILE, 3), np.uint8)
        canvas[:] = BG
        for (x, y), i in frag["cells"].items():
            canvas[y * TILE:(y + 1) * TILE, x * TILE:(x + 1) * TILE] = self.t8[i]
        return Image.fromarray(canvas)


# =============================================================================== per cache / case
def reconstruct_dir(tile_dir: Path, out_dir: Path, prefix: str, min_tiles: int = 4,
                    max_mse: float = 150.0, ratio: float = 0.85,
                    progress: Callable[[str], None] | None = None) -> dict:
    """Reconstruct one bmc-tools output folder. Returns stats and the written fragment images."""
    names, tiles = load_tiles(tile_dir)
    st = Stitcher(tiles, max_mse=max_mse, ratio=ratio, progress=progress)
    frags = st.solve(min_tiles)
    res = {"tiles": len(names), "unique": len(st.active), "uniform": int(st.uniform.sum()),
           "fragments": [], "placed": 0}
    if not frags:
        return res
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for k, f in enumerate(frags, 1):
        img = f"{prefix}_frag{k:03d}_{f['cols']}x{f['rows']}_{len(f['cells'])}t.png"
        st.render(f).save(out_dir / img)
        res["fragments"].append({"image": img, "tiles": len(f["cells"]), "matched": f["matched"],
                                 "cols": f["cols"], "rows": f["rows"]})
        res["placed"] += f["matched"]
        for (x, y), i in sorted(f["cells"].items(), key=lambda c: (c[0][1], c[0][0])):
            rows.append([k, img, x, y, names[i], "filled" if (x, y) in f["filled"] else "matched"])
    with open(out_dir / f"{prefix}_fragments.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Fragment", "Image", "Column", "Row", "TileFile", "Placement"])
        w.writerows(rows)
    return res


def write_gallery(out_root: Path, host: str, results: dict[str, dict]) -> Path:
    """index.html with every fragment, largest first, grouped per cache file."""
    parts = [f"<!doctype html><meta charset='utf-8'><title>{html.escape(host)} - RDP cache reconstruction</title>",
             "<style>body{background:#111;color:#ddd;font:14px system-ui,sans-serif;margin:16px}"
             "h2{color:#8fd3ff;border-bottom:1px solid #333;padding-bottom:4px}"
             ".g{display:flex;flex-wrap:wrap;gap:12px}.f{background:#1b1b1b;padding:6px;border-radius:4px}"
             ".f img{max-width:640px;max-height:420px;image-rendering:pixelated;display:block}"
             ".f span{color:#999;font-size:12px}</style>",
             f"<h1>{html.escape(host)} &middot; RDP bitmap cache reconstruction</h1>",
             "<p>Fragments rebuilt automatically from bmc-tools tiles by border matching. Grey cells = no tile "
             "found. Every tile position is listed in the matching *_fragments.csv. Verify important findings "
             "against the original tiles (e.g. with RdpCacheStitcher).</p>"]
    for cache, r in results.items():
        parts.append(f"<h2>{html.escape(cache)}</h2><p>{r['tiles']} tiles, {r['unique']} unique non-uniform, "
                     f"{len(r['fragments'])} fragments, {r['placed']} tiles placed by matching</p><div class='g'>")
        for f in r["fragments"]:
            src = html.escape(f"{cache}/{f['image']}")
            parts.append(f"<div class='f'><a href='{src}'><img loading='lazy' src='{src}'></a>"
                         f"<span>{html.escape(f['image'])} &middot; {f['tiles']} tiles</span></div>")
        parts.append("</div>")
    p = out_root / f"{host}_RDP_Reconstruction.html"
    p.write_text("\n".join(parts), encoding="utf-8")
    return p
