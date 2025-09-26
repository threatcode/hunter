"""
In-memory graph database for attack path analysis.

This module builds a graph representation of assets and findings to enable
attack path analysis.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Any, Set

from automation.database import get_db_session, finding_repository, asset_repository
from data.schemas import Asset, Finding, AssetType


logger = logging.getLogger(__name__)


class GraphDB:
    """Builds and manages an in-memory graph of assets and vulnerabilities."""
    
    def __init__(self):
        self.graph = defaultdict(list)
        self.nodes = {}
    
    def build_graph_from_db(self):
        """Build the graph from assets and findings in the database."""
        
        logger.info("Building attack path graph from database...")
        
        with get_db_session() as session:
            assets = asset_repository.get_all(session)
            findings = finding_repository.get_all(session)
        
        # Add assets as nodes
        for asset in assets:
            self.nodes[asset.id] = {'type': asset.type.value, 'name': asset.name, 'asset': asset}
        
        # Add relationships based on findings
        for finding in findings:
            if not finding.asset_id or finding.asset_id not in self.nodes:
                continue
            
            # Create a vulnerability node
            vuln_id = f"vuln-{finding.id}"
            self.nodes[vuln_id] = {'type': 'vulnerability', 'name': finding.title, 'finding': finding}
            
            # Add an edge from the asset to the vulnerability
            self._add_edge(finding.asset_id, vuln_id, 'IS_VULNERABLE_TO')
            
            # Add edges based on vulnerability type (potential for chaining)
            self._add_contextual_edges(finding, vuln_id)
        
        logger.info(f"Graph built with {len(self.nodes)} nodes and {sum(len(v) for v in self.graph.values())} edges.")

    def _add_edge(self, source_node_id: str, dest_node_id: str, relationship: str):
        """Add a directed edge to the graph."""
        
        if source_node_id in self.nodes and dest_node_id in self.nodes:
            self.graph[source_node_id].append({'target': dest_node_id, 'rel': relationship})
    
    def _add_contextual_edges(self, finding: Finding, vuln_id: str):
        """Add edges that represent the potential impact of a vulnerability."""
        
        # If RCE, the vulnerability can lead to control of the host
        if finding.vulnerability_type.value in ['RCE', 'COMMAND_INJECTION']:
            # Assuming the asset_id is a URL, we need to find the host asset
            # This is a simplification; a real implementation would have more robust asset mapping
            host_asset_id = self._find_host_for_asset(finding.asset_id)
            if host_asset_id:
                self._add_edge(vuln_id, host_asset_id, 'CAN_COMPROMISE')
        
        # If SQLi, it can lead to compromise of a database
        if finding.vulnerability_type.value == 'SQLI':
            # Create a conceptual database node and link it
            db_id = f"db-for-{finding.asset_id}"
            if db_id not in self.nodes:
                self.nodes[db_id] = {'type': 'database', 'name': f"Database for {finding.asset_id}"}
            self._add_edge(vuln_id, db_id, 'CAN_COMPROMISE')

    def _find_host_for_asset(self, asset_id: str) -> str or None:
        """Find the host asset that contains a given asset (e.g., a URL)."""
        # This is a simple heuristic. A more robust system would have explicit asset relationships.
        for node_id, node_data in self.nodes.items():
            if node_data['type'] == AssetType.HOST.value and node_data['name'] in asset_id:
                return node_id
        return None

    def get_node(self, node_id: str) -> Dict[str, Any] or None:
        """Get a node by its ID."""
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        """Get the neighbors of a node."""
        return self.graph.get(node_id, [])


# Standalone usage
if __name__ == "__main__":
    def test_graph_build():
        print("Building graph from database...")
        try:
            graph_db = GraphDB()
            graph_db.build_graph_from_db()
            
            print("Graph built successfully.")
            print(f"Total nodes: {len(graph_db.nodes)}")
            
            # Print a few nodes and their relationships
            for i, (node_id, relations) in enumerate(graph_db.graph.items()):
                if i >= 5:
                    break
                print(f"\nNode: {graph_db.get_node(node_id)['name']}")
                for rel in relations:
                    target_node = graph_db.get_node(rel['target'])
                    print(f"  --[{rel['rel']}]--> {target_node['name']}")
        
        except Exception as e:
            print(f"Graph build failed: {e}")
            print("Please ensure your database is populated with assets and findings.")

    # test_graph_build()
