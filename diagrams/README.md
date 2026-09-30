# Diagrams

Mermaid sources (`.mmd`) and their rendered `.svg` output, embedded in the top-level
[`README.md`](../README.md). Edit the `.mmd` file, then re-render the matching `.svg`.

| File | Shows |
|---|---|
| `architecture` | The two-lane system: gateway + engine inline, analyst out of band. |
| `request-lifecycle` | A request from client to verdict to app (sequence). |
| `decision-flow` | How L0, the models, hard signals, the denylist and the mode produce a verdict. |
| `feedback-loop` | Findings → time-limited denylist → inline enforcement → expiry. |
| `deployment` | Container topology of a deployment unit (compose project or k8s pod). |

## Regenerate

Rendered with [mermaid-cli](https://github.com/mermaid-js/mermaid-cli) via Docker,
using a white background so the diagrams read on both light and dark themes:

```sh
cd diagrams
for f in architecture request-lifecycle decision-flow feedback-loop deployment; do
  docker run --rm -u 0 --cap-add=SYS_ADMIN --shm-size=512m -v "$PWD":/data \
    minlag/mermaid-cli:11.4.2 -i "/data/$f.mmd" -o "/data/$f.svg" -t neutral -b white
done
```

`--cap-add=SYS_ADMIN` lets the bundled headless Chromium start inside the container.
