"""
AI-powered attack path analysis engine.

This module analyzes the graph of assets and vulnerabilities to identify
potential attack chains.
"""

import logging
from typing import Dict, List, Any, Set, Tuple

from ai.graph_db import GraphDB


logger = logging.getLogger(__name__)


class AttackPathAnalyzer:
    """Analyzes the security graph to find potential attack paths."""
    
    def __init__(self, graph_db: GraphDB):
        self.graph_db = graph_db
    
    def find_attack_paths(self, start_node_id: str, goal_node_id: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        """Find all attack paths from a start node to a goal node."""
        
        logger.info(f"Searching for attack paths from {start_node_id} to {goal_node_id}")
        
        paths = []
        queue: List[Tuple[str, List[Dict[str, Any]], Set[str]]] = [(start_node_id, [], {start_node_id})]
        
        while queue:
            current_node_id, path, visited = queue.pop(0)
            
            if len(path) >= max_depth:
                continue
            
            neighbors = self.graph_db.get_neighbors(current_node_id)
            for edge in neighbors:
                neighbor_id = edge['target']
                
                if neighbor_id in visited:
                    continue
                
                new_path = path + [{'node_id': current_node_id, 'edge': edge['rel'], 'target_id': neighbor_id}]
                
                if neighbor_id == goal_node_id:
                    paths.append({
                        'path': new_path,
                        'length': len(new_path),
                        'score': self._score_path(new_path)
                    })
                else:
                    new_visited = visited.copy()
                    new_visited.add(neighbor_id)
                    queue.append((neighbor_id, new_path, new_visited))
        
        # Sort paths by score (higher is more critical)
        paths.sort(key=lambda p: p['score'], reverse=True)
        
        logger.info(f"Found {len(paths)} potential attack paths.")
        return paths
    
    def find_all_paths_to_high_value_assets(self, start_node_ids: List[str], max_depth: int = 5) -> List[Dict[str, Any]]:
        """Find all attack paths from a set of entry points to any high-value asset."""
        
        high_value_assets = self._identify_high_value_assets()
        all_paths = []
        
        for start_node in start_node_ids:
            for goal_node in high_value_assets:
                if start_node != goal_node:
                    paths = self.find_attack_paths(start_node, goal_node, max_depth)
                    all_paths.extend(paths)
        
        # Sort all found paths by score
        all_paths.sort(key=lambda p: p['score'], reverse=True)
        
        return all_paths

    def _identify_high_value_assets(self) -> List[str]:
        """Identify high-value assets in the graph (e.g., hosts, databases)."""
        
        high_value_nodes = []
        for node_id, node_data in self.graph_db.nodes.items():
            if node_data['type'] in ['host', 'database']:
                high_value_nodes.append(node_id)
        return high_value_nodes

    def _score_path(self, path: List[Dict[str, Any]]) -> float:
        """Score an attack path based on the severity of its vulnerabilities."""
        
        score = 0.0
        severity_scores = {
            'CRITICAL': 10.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 1.0,
            'INFORMATIONAL': 0.1
        }
        
        for step in path:
            node_id = step['target_id']
            node = self.graph_db.get_node(node_id)
            if node and node['type'] == 'vulnerability':
                finding = node.get('finding')
                if finding:
                    score += severity_scores.get(finding.severity.value.upper(), 0.0)
        
        # Penalize longer paths
        return score / (len(path) if path else 1)
    
    def format_path(self, path_data: Dict[str, Any]) -> str:
        """Format an attack path into a human-readable string."""
        
        formatted_path = ""
        for i, step in enumerate(path_data['path']):
            start_node = self.graph_db.get_node(step['node_id'])
            end_node = self.graph_db.get_node(step['target_id'])
            
            if start_node and end_node:
                formatted_path += f"{i+1}. {start_node['name']} --[{step['edge']}]--> {end_node['name']}\n"
        
        return formatted_path


# Standalone usage
if __name__ == "__main__":
    def test_attack_path_analysis():
        print("Running attack path analysis test...")
        try:
            graph_db = GraphDB()
            graph_db.build_graph_from_db()
            
            analyzer = AttackPathAnalyzer(graph_db)
            
            # Identify entry points (e.g., public-facing web apps)
            entry_points = [node_id for node_id, node in graph_db.nodes.items() if node['type'] == 'WEB_APPLICATION']
            
            if not entry_points:
                print("No entry points found for analysis.")
                return

            print(f"Analyzing paths from {len(entry_points)} entry points...")
            
            all_paths = analyzer.find_all_paths_to_high_value_assets(entry_points)
            
            if not all_paths:
                print("No attack paths found.")
                return
            
            print(f"\nFound {len(all_paths)} potential attack paths. Top 3:")
            for i, path_data in enumerate(all_paths[:3]):
                print(f"\n--- Path #{i+1} (Score: {path_data['score']:.2f}) ---")
                print(analyzer.format_path(path_data))
        
        except Exception as e:
            print(f"Attack path analysis failed: {e}")

    # test_attack_path_analysis()
