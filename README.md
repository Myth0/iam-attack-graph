# iam-attack-graph
YO! This is MY first time to beark the virgin(ahmm) of my github with this project  Attack path analysis for AWS IAM — finds privilege escalation chains from a compromised principal to AdministratorAccess

The engine has zero knowledge of the API or frontend, and is fully usable standalone via the CLI. This separation is deliberate: the detection logic is the core intellectual work of this project, and it's tested and runnable independently of any web layer.

## Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Detection engine | Python 3.13, `networkx`, `pydantic` | `networkx` for graph/path algorithms rather than hand-rolling them; `pydantic` for strict validation of untrusted uploaded JSON |
| API | FastAPI | Async, built-in request validation, auto-generated OpenAPI docs |
| Frontend | React 19 + Vite | Fast dev experience, modern React |
| Graph visualization | Cytoscape.js (`react-cytoscapejs`) | Purpose-built for graph *analysis* interactions (node/edge selection, path tracing), not just force-directed aesthetics |
| Testing | `pytest`, FastAPI `TestClient` | Real unit and integration tests, not just manual smoke checks |
| CI | GitHub Actions | Runs the full test suite on every push |

## Installation

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### Backend

```bash
git clone https://github.com/Myth0/iam-attack-graph.git
cd iam-attack-graph
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend

```bash
cd frontend
npm install
```

## Usage

### Option 1 — Web UI (recommended)

Terminal 1 (backend):
```bash
source venv/bin/activate
uvicorn api.main:app --reload --port 8000
```

Terminal 2 (frontend):
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173`, upload an IAM export JSON file, and click **Analyze**.

### Option 2 — CLI

```bash
python -m engine.cli path/to/iam_export.json
```

### Getting an IAM export to analyze

```bash
aws iam get-account-authorization-details > iam_export.json
```

This requires `iam:GetAccountAuthorizationDetails` permission. **This tool never runs this command for you** — it only ever analyzes a file you provide, keeping the entire analysis workflow read-only and disconnected from any live AWS credentials.

A sample fixture with a deliberate self-privesc scenario is included at `tests/fixtures/sample_iam_export.json` for trying the tool immediately without any AWS account.

## Security Considerations

- **Read-only, analysis-only.** This tool never calls any AWS API that creates, modifies, or deletes anything. It only parses IAM export JSON that you provide.
- **No data persistence.** The backend is fully stateless — uploaded files are processed entirely in memory and are never written to disk or logged.
- **Upload size capped at 5MB** to prevent abuse of the public demo (if deployed).
- **Do not upload real production IAM data to a public-facing deployment of this tool.** Use a sanitized export or a lab account. See `THREAT_MODEL.md` for the full analysis.
- **Known v1 limitation:** the engine does not currently evaluate Service Control Policies (SCPs) or permission boundaries, since these require AWS Organization-level data not included in a standard account authorization export. A path flagged by this tool could theoretically be blocked by an SCP not visible to the engine. Always verify findings against your account's actual SCP configuration before treating them as exploitable.

## Screenshots

*Coming soon — the web UI is fully functional (upload form, interactive graph with severity-colored nodes, findings panel), screenshots will be added here shortly.*

## Demo

**Live app:** https://iam-attack-graph-frontend.vercel.app
**Live API:** https://iam-attack-graph-api.vercel.app (interactive docs at `/docs`)

Try it immediately with the included sample fixture (`tests/fixtures/sample_iam_export.json`) — no AWS account required. It contains a deliberate self-privilege-escalation scenario for `test-user`.

## Documentation

- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — full threat model for both the analysis tool itself and its public deployment
- Interactive API docs available at `/docs` when running the backend locally (FastAPI auto-generated)

## Future Improvements

- Additional privesc techniques from the broader documented AWS IAM taxonomy (e.g. `iam:CreateAccessKey` on another user, Lambda-based escalation chains)
- Live AWS API mode (read-only `iam:Get*`/`iam:List*` permissions) as an alternative to file upload
- Multi-account / AWS Organizations cross-account escalation path analysis
- SCP and permission boundary awareness
- Path-tracing UI: click any node, highlight the full path to `AdministratorAccess`

## License

MIT — see [`LICENSE`](./LICENSE).
