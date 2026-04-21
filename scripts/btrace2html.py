#!/usr/bin/env python3
"""
btrace2html.py — Convert btrace DOT + stacks JSON into an interactive HTML page.

Usage:
    python3 scripts/btrace2html.py out/btrace.dot -o out/btrace.html

Click any edge to see a popup with blocked (left) and waker (right) kernel stacks.
"""

import argparse
import json
import os
import re
import subprocess
import sys


def dot_to_svg(dot_path):
    r = subprocess.run(["dot", "-Tsvg", dot_path], capture_output=True)
    if r.returncode != 0:
        print(f"dot failed: {r.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    return r.stdout.decode()


def load_stacks(dot_path):
    base, _ = os.path.splitext(dot_path)
    json_path = base + "_stacks.json"
    if not os.path.exists(json_path):
        json_path = dot_path.replace(".dot", "_stacks.json")
    if not os.path.exists(json_path):
        print(f"Warning: {json_path} not found, no stack data", file=sys.stderr)
        return {}
    with open(json_path) as f:
        return json.load(f)


def build_tooltip_map(stacks):
    """Build tooltip_text -> edgeid map from stacks JSON."""
    m = {}
    for eid, data in stacks.items():
        parts = []
        for s in (data.get("blocked_stack") or []):
            parts.append(s)
        for s in (data.get("waker_stack") or []):
            parts.append(s)
        m[eid] = data
    return m


def patch_svg(svg, stacks):
    """Inject data-edgeid attributes into SVG edge groups by matching
    tooltip text from xlink:title attributes to the stacks JSON."""
    tooltip_to_eid = {}
    for eid, data in stacks.items():
        # Tooltip format: "TID comm -> TID comm | cat dur, Nx"
        # "from" is "TID (comm)" and "to" is "TID (comm)" or "[cat]"
        from_str = data['from'].replace(' (', ' ').rstrip(')')
        to_str = data['to'].replace(' (', ' ').rstrip(')')
        tip = f"{from_str} -> {to_str} | {data['block_cat']} {data['duration']}, {data['count']}x"
        tooltip_to_eid[tip] = eid

    # Parse line by line: find <g ... class="edge"...> and look ahead for
    # xlink:title within that group. Inject data-edgeid on the opening <g>.
    lines = svg.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'(\s*<g\s+)([^>]*class="edge"[^>]*)>', line)
        if m:
            edge_block = line
            j = i + 1
            depth = 1
            for k in range(j, min(j + 20, len(lines))):
                edge_block += '\n' + lines[k]
                depth += lines[k].count('<g') - lines[k].count('</g>')
                if depth <= 0:
                    break
            title_m = re.search(r'xlink:title="([^"]*)"', edge_block)
            if title_m:
                tip = title_m.group(1)
                tip = tip.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&")
                tip = tip.replace("&#45;", "-").replace("&#62;", ">").replace("&#38;", "&")
                eid = tooltip_to_eid.get(tip)
                if eid:
                    line = m.group(1) + f'data-edgeid="{eid}" ' + m.group(2) + '>'
        result.append(line)
        i += 1
    return '\n'.join(result)


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>btrace viewer</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       background: #f5f5f5; color: #333; }
#container { max-width: 100%; overflow: auto; padding: 12px; }
#container svg { max-width: 100%; height: auto; }
#container svg .edge { cursor: pointer; }
#container svg .edge:hover path { stroke-width: 3; }
#container svg .edge:hover polygon { stroke-width: 2; }
#container svg text { user-select: none; }

#modal-overlay {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,0.45); z-index: 100;
    justify-content: center; align-items: center;
}
#modal-overlay.active { display: flex; }
#modal {
    background: #fff; border-radius: 10px; padding: 24px 28px;
    max-width: 720px; width: 90%; max-height: 85vh; overflow-y: auto;
    box-shadow: 0 8px 32px rgba(0,0,0,0.25);
}
#modal-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #e0e0e0;
}
#modal-header h3 { font-size: 14px; font-weight: 600; color: #555; }
#modal-close {
    background: none; border: none; font-size: 22px; cursor: pointer;
    color: #999; line-height: 1;
}
#modal-close:hover { color: #333; }
#modal-meta {
    display: flex; gap: 16px; margin-bottom: 14px;
    font-size: 13px; color: #666; flex-wrap: wrap;
}
#modal-meta span { background: #f0f0f0; padding: 2px 8px; border-radius: 4px; }
#stacks-container { display: flex; gap: 24px; }
.stack-col { flex: 1; min-width: 0; }
.stack-col h4 {
    font-size: 12px; font-weight: 600; text-transform: uppercase;
    color: #888; margin-bottom: 8px; letter-spacing: 0.5px;
}
.stack-col.blocked h4 { color: #c0392b; }
.stack-col.waker h4 { color: #2980b9; }
.stack-frames {
    background: #fafafa; border: 1px solid #e8e8e8; border-radius: 6px;
    padding: 8px 0; font-family: "SF Mono", "Fira Code", "Consolas", monospace;
    font-size: 11.5px; line-height: 1.7;
}
.stack-frames .frame {
    padding: 1px 10px; white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis;
}
.stack-frames .frame:nth-child(odd) { background: #f5f5f5; }
.stack-frames .frame:first-child { font-weight: 600; }
</style>
</head>
<body>
<div id="container">
{{SVG}}
</div>

<div id="modal-overlay">
<div id="modal">
  <div id="modal-header">
    <h3 id="modal-title"></h3>
    <button id="modal-close">&times;</button>
  </div>
  <div id="modal-meta"></div>
  <div id="stacks-container">
    <div class="stack-col blocked">
      <h4>Blocked stack (waiter)</h4>
      <div class="stack-frames" id="blocked-frames"></div>
    </div>
    <div class="stack-col waker">
      <h4>Waker stack (blocker)</h4>
      <div class="stack-frames" id="waker-frames"></div>
    </div>
  </div>
</div>
</div>

<script>
const STACKS = {{STACKS_JSON}};

function showModal(edgeid) {
    const data = STACKS[edgeid];
    if (!data) return;
    document.getElementById('modal-title').textContent =
        data.from + ' \u2192 ' + data.to;
    document.getElementById('modal-meta').innerHTML =
        '<span>' + data.block_cat + '</span>' +
        '<span>' + data.waker_cat + '</span>' +
        '<span>' + data.duration + '</span>' +
        '<span>' + data.count + ' samples</span>';
    const bf = document.getElementById('blocked-frames');
    bf.innerHTML = '';
    (data.blocked_stack || []).forEach(function(s) {
        const d = document.createElement('div');
        d.className = 'frame';
        d.textContent = s;
        bf.appendChild(d);
    });
    const wf = document.getElementById('waker-frames');
    wf.innerHTML = '';
    (data.waker_stack || []).forEach(function(s) {
        const d = document.createElement('div');
        d.className = 'frame';
        d.textContent = s;
        wf.appendChild(d);
    });
    document.getElementById('modal-overlay').classList.add('active');
}

function hideModal() {
    document.getElementById('modal-overlay').classList.remove('active');
}

document.getElementById('modal-overlay').addEventListener('click', function(e) {
    if (e.target === this) hideModal();
});
document.getElementById('modal-close').addEventListener('click', hideModal);
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') hideModal();
});

document.querySelectorAll('.edge[data-edgeid]').forEach(function(g) {
    g.addEventListener('click', function() {
        showModal(g.getAttribute('data-edgeid'));
    });
});
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Convert btrace DOT to interactive HTML")
    parser.add_argument("dot", help="Input .dot file (from btrace report --dot)")
    parser.add_argument("-o", "--output", help="Output .html file (default: same base name)")
    args = parser.parse_args()

    if not os.path.exists(args.dot):
        print(f"Error: {args.dot} not found", file=sys.stderr)
        sys.exit(1)

    out_path = args.output
    if not out_path:
        base, _ = os.path.splitext(args.dot)
        out_path = base + ".html"

    svg = dot_to_svg(args.dot)
    stacks = load_stacks(args.dot)

    svg = patch_svg(svg, stacks)

    html = HTML_TEMPLATE.replace("{{SVG}}", svg)
    html = html.replace("{{STACKS_JSON}}", json.dumps(stacks))

    with open(out_path, 'w') as f:
        f.write(html)

    print(f"Interactive HTML written to {out_path}")


if __name__ == "__main__":
    main()
