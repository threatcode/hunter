"""
Celery tasks for advanced AI capabilities.

This module contains tasks for running computationally intensive AI analyses,
like attack path analysis, in the background.
"""

import logging

from celery import Task
from automation.orchestrator import celery_app
from ai.graph_db import GraphDB
from ai.attack_path_analyzer import AttackPathAnalyzer
from data.schemas import AssetType


logger = logging.getLogger(__name__)


class BaseAITask(Task):
    """Base class for AI tasks."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"AI task {task_id} failed: {exc}")
    
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"AI task {task_id} completed successfully")


@celery_app.task(bind=True, base=BaseAITask, name='ai.tasks.run_attack_path_analysis')
def run_attack_path_analysis(self, max_paths: int = 10):
    """Run the AI-powered attack path analysis."""
    
    logger.info("Starting AI attack path analysis...")
    
    try:
        # 1. Build the graph
        graph_db = GraphDB()
        graph_db.build_graph_from_db()
        
        # 2. Initialize the analyzer
        analyzer = AttackPathAnalyzer(graph_db)
        
        # 3. Identify entry points (e.g., public-facing web apps)
        entry_points = [
            node_id for node_id, node in graph_db.nodes.items() 
            if node['type'] == AssetType.WEB_APPLICATION.value
        ]
        
        if not entry_points:
            logger.warning("No entry points found for attack path analysis.")
            return {'status': 'completed', 'paths': [], 'message': 'No entry points found.'}

        # 4. Find all paths to high-value assets
        all_paths = analyzer.find_all_paths_to_high_value_assets(entry_points)
        
        # 5. Format and return the top paths
        formatted_paths = []
        for path_data in all_paths[:max_paths]:
            formatted_paths.append({
                'score': path_data['score'],
                'length': path_data['length'],
                'path_str': analyzer.format_path(path_data),
                'path_details': path_data['path']
            })
        
        result = {
            'status': 'completed',
            'paths_found': len(all_paths),
            'paths': formatted_paths
        }
        
        logger.info(f"Attack path analysis completed. Found {len(all_paths)} paths.")
        return result

    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}")
        raise
