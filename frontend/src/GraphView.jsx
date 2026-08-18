import CytoscapeComponent from 'react-cytoscapejs';

function buildElements(graph, findings) {
  // Map of arn -> highest severity finding for that principal (if any)
  const severityByArn = {};
  for (const f of findings) {
    const current = severityByArn[f.principal_arn];
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    if (!current || rank[f.severity] < rank[current]) {
      severityByArn[f.principal_arn] = f.severity;
    }
  }

  const nodes = graph.nodes.map((n) => ({
    data: {
      id: n.id,
      label: n.name,
      type: n.type,
      severity: severityByArn[n.id] || null,
    },
  }));

  const edges = graph.edges.map((e, i) => ({
    data: {
      id: `edge-${i}`,
      source: e.source,
      target: e.target,
      label: e.relationship,
    },
  }));

  return [...nodes, ...edges];
}

const stylesheet = [
  {
    selector: 'node',
    style: {
      label: 'data(label)',
      'background-color': '#888',
      color: '#222',
      'font-size': 10,
      'text-valign': 'bottom',
      'text-margin-y': 6,
      width: 30,
      height: 30,
    },
  },
  {
    selector: 'node[type = "User"]',
    style: { shape: 'ellipse', 'background-color': '#4a90d9' },
  },
  {
    selector: 'node[type = "Role"]',
    style: { shape: 'round-rectangle', 'background-color': '#7a5cc4' },
  },
  {
    selector: 'node[type = "Group"]',
    style: { shape: 'diamond', 'background-color': '#4caf50' },
  },
  {
    selector: 'node[severity = "critical"]',
    style: { 'background-color': '#c0392b', 'border-width': 3, 'border-color': '#7a1f14' },
  },
  {
    selector: 'node[severity = "high"]',
    style: { 'background-color': '#e67e22', 'border-width': 3, 'border-color': '#a85c15' },
  },
  {
    selector: 'edge',
    style: {
      label: 'data(label)',
      'font-size': 8,
      'curve-style': 'bezier',
      'target-arrow-shape': 'triangle',
      width: 2,
      'line-color': '#aaa',
      'target-arrow-color': '#aaa',
    },
  },
];

function GraphView({ graph, findings }) {
  const elements = buildElements(graph, findings);

  return (
    <div className="graph-container">
      <CytoscapeComponent
        elements={elements}
        stylesheet={stylesheet}
        layout={{ name: 'cose', animate: false }}
        style={{ width: '100%', height: '500px', border: '1px solid #ddd', borderRadius: '4px' }}
      />
    </div>
  );
}

export default GraphView;
