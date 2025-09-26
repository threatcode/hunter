"""
AI services integration for the Bug Hunter framework.

This module provides LLM and embedding services for vulnerability analysis,
PoC generation, and intelligent triage.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from abc import ABC, abstractmethod
import openai
from sentence_transformers import SentenceTransformer
import numpy as np
from dataclasses import dataclass

from data.schemas import Finding, VulnerabilityType, SeverityLevel
from automation.logging_config import audit_logger


logger = logging.getLogger(__name__)


@dataclass
class PromptTemplate:
    """Template for LLM prompts."""
    name: str
    template: str
    variables: List[str]
    description: str


class BaseLLMProvider(ABC):
    """Base class for LLM providers."""
    
    @abstractmethod
    async def generate_text(self, prompt: str, **kwargs) -> str:
        """Generate text from a prompt."""
        pass
    
    @abstractmethod
    async def generate_structured(self, prompt: str, schema: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Generate structured output from a prompt."""
        pass


class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        
        if not self.api_key:
            raise ValueError("OpenAI API key not provided")
        
        openai.api_key = self.api_key
    
    async def generate_text(self, prompt: str, **kwargs) -> str:
        """Generate text using OpenAI."""
        try:
            response = await openai.ChatCompletion.acreate(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=kwargs.get("max_tokens", 1000),
                temperature=kwargs.get("temperature", 0.7)
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"OpenAI text generation failed: {e}")
            raise
    
    async def generate_structured(self, prompt: str, schema: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Generate structured output using OpenAI."""
        try:
            # Add schema to prompt
            structured_prompt = f"{prompt}\n\nPlease respond with valid JSON matching this schema:\n{json.dumps(schema, indent=2)}"
            
            response = await openai.ChatCompletion.acreate(
                model=self.model,
                messages=[{"role": "user", "content": structured_prompt}],
                max_tokens=kwargs.get("max_tokens", 1500),
                temperature=kwargs.get("temperature", 0.3)
            )
            
            content = response.choices[0].message.content.strip()
            
            # Try to parse JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Extract JSON from response if it's wrapped in text
                import re
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
                else:
                    raise ValueError("Could not extract valid JSON from response")
        
        except Exception as e:
            logger.error(f"OpenAI structured generation failed: {e}")
            raise


class EmbeddingService:
    """Service for generating and managing embeddings."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.model_name = model_name
    
    def encode_text(self, text: str) -> np.ndarray:
        """Encode text into embeddings."""
        return self.model.encode(text)
    
    def encode_batch(self, texts: List[str]) -> np.ndarray:
        """Encode multiple texts into embeddings."""
        return self.model.encode(texts)
    
    def similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Calculate cosine similarity between embeddings."""
        from sklearn.metrics.pairwise import cosine_similarity
        return cosine_similarity([embedding1], [embedding2])[0][0]
    
    def find_similar(self, query_embedding: np.ndarray, embeddings: List[np.ndarray], top_k: int = 5) -> List[int]:
        """Find most similar embeddings."""
        similarities = [self.similarity(query_embedding, emb) for emb in embeddings]
        # Get indices of top_k most similar
        return sorted(range(len(similarities)), key=lambda i: similarities[i], reverse=True)[:top_k]


class PromptManager:
    """Manager for LLM prompt templates."""
    
    def __init__(self):
        self.templates = {}
        self._load_default_templates()
    
    def add_template(self, template: PromptTemplate) -> None:
        """Add a prompt template."""
        self.templates[template.name] = template
    
    def get_template(self, name: str) -> Optional[PromptTemplate]:
        """Get a prompt template by name."""
        return self.templates.get(name)
    
    def render_template(self, name: str, **variables) -> str:
        """Render a template with variables."""
        template = self.get_template(name)
        if not template:
            raise ValueError(f"Template '{name}' not found")
        
        # Check if all required variables are provided
        missing_vars = set(template.variables) - set(variables.keys())
        if missing_vars:
            raise ValueError(f"Missing template variables: {missing_vars}")
        
        return template.template.format(**variables)
    
    def _load_default_templates(self) -> None:
        """Load default prompt templates."""
        
        # Vulnerability analysis template
        vuln_analysis = PromptTemplate(
            name="vulnerability_analysis",
            template="""
Analyze this potential security vulnerability:

URL: {url}
Method: {method}
Parameter: {parameter}
Payload: {payload}
Response: {response}
Status Code: {status_code}

Please provide:
1. Vulnerability type classification
2. Severity assessment (Critical/High/Medium/Low/Info)
3. Confidence level (0.0-1.0)
4. Detailed explanation
5. Potential impact
6. Recommended remediation

Be thorough but concise in your analysis.
""",
            variables=["url", "method", "parameter", "payload", "response", "status_code"],
            description="Analyze potential vulnerabilities from scan results"
        )
        
        # PoC generation template
        poc_generation = PromptTemplate(
            name="poc_generation",
            template="""
Generate a proof-of-concept for this vulnerability:

Vulnerability Type: {vuln_type}
Target URL: {url}
Vulnerable Parameter: {parameter}
Description: {description}

Create:
1. Step-by-step reproduction instructions
2. curl command example
3. Python script (if applicable)
4. Expected vs actual results
5. Screenshots/evidence needed

Make the PoC clear, safe, and reproducible.
""",
            variables=["vuln_type", "url", "parameter", "description"],
            description="Generate proof-of-concept for vulnerabilities"
        )
        
        # Recon summarization template
        recon_summary = PromptTemplate(
            name="recon_summary",
            template="""
Summarize this reconnaissance data for target: {target}

Data collected:
{recon_data}

Provide:
1. Key findings summary
2. Attack surface overview
3. High-priority targets identified
4. Recommended next steps
5. Potential security concerns

Focus on actionable intelligence for security testing.
""",
            variables=["target", "recon_data"],
            description="Summarize reconnaissance findings"
        )
        
        # Triage recommendation template
        triage_recommendation = PromptTemplate(
            name="triage_recommendation",
            template="""
Provide triage recommendations for this finding:

Title: {title}
Severity: {severity}
Vulnerability Type: {vuln_type}
URL: {url}
Description: {description}
Evidence: {evidence}

Consider:
1. Business impact assessment
2. Exploitability factors
3. False positive likelihood
4. Verification priority
5. Remediation urgency

Provide clear triage decision and reasoning.
""",
            variables=["title", "severity", "vuln_type", "url", "description", "evidence"],
            description="Provide intelligent triage recommendations"
        )
        
        # Add templates
        for template in [vuln_analysis, poc_generation, recon_summary, triage_recommendation]:
            self.add_template(template)


class VulnerabilityAnalyzer:
    """AI-powered vulnerability analyzer."""
    
    def __init__(self, llm_provider: BaseLLMProvider, embedding_service: EmbeddingService):
        self.llm = llm_provider
        self.embeddings = embedding_service
        self.prompt_manager = PromptManager()
    
    async def analyze_potential_vulnerability(
        self,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        response: str,
        status_code: int
    ) -> Dict[str, Any]:
        """Analyze a potential vulnerability using AI."""
        
        try:
            # Render analysis prompt
            prompt = self.prompt_manager.render_template(
                "vulnerability_analysis",
                url=url,
                method=method,
                parameter=parameter,
                payload=payload,
                response=response[:2000],  # Truncate long responses
                status_code=status_code
            )
            
            # Define expected schema
            schema = {
                "vulnerability_type": "string",
                "severity": "string",
                "confidence": "number",
                "explanation": "string",
                "impact": "string",
                "remediation": "string",
                "is_vulnerability": "boolean"
            }
            
            # Get AI analysis
            analysis = await self.llm.generate_structured(prompt, schema)
            
            # Log the analysis
            audit_logger.log_security_event(
                "ai_vulnerability_analysis",
                f"AI analyzed potential vulnerability at {url}",
                url=url,
                confidence=analysis.get("confidence", 0),
                vulnerability_type=analysis.get("vulnerability_type", "unknown")
            )
            
            return analysis
        
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            return {
                "vulnerability_type": "unknown",
                "severity": "info",
                "confidence": 0.0,
                "explanation": f"Analysis failed: {e}",
                "impact": "Unknown",
                "remediation": "Manual review required",
                "is_vulnerability": False
            }
    
    async def generate_poc(self, finding: Finding) -> Dict[str, Any]:
        """Generate proof-of-concept for a finding."""
        
        try:
            prompt = self.prompt_manager.render_template(
                "poc_generation",
                vuln_type=finding.vulnerability_type.value,
                url=str(finding.affected_url) if finding.affected_url else "N/A",
                parameter=finding.affected_parameter or "N/A",
                description=finding.description
            )
            
            schema = {
                "steps": ["string"],
                "curl_command": "string",
                "python_script": "string",
                "expected_result": "string",
                "actual_result": "string",
                "evidence_needed": ["string"]
            }
            
            poc = await self.llm.generate_structured(prompt, schema)
            
            # Log PoC generation
            audit_logger.log_security_event(
                "poc_generated",
                f"AI generated PoC for finding {finding.id}",
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type.value
            )
            
            return poc
        
        except Exception as e:
            logger.error(f"PoC generation failed: {e}")
            return {
                "steps": ["Manual verification required"],
                "curl_command": "# PoC generation failed",
                "python_script": "# PoC generation failed",
                "expected_result": "Unknown",
                "actual_result": "Unknown",
                "evidence_needed": ["Manual analysis"]
            }
    
    async def triage_finding(self, finding: Finding) -> Dict[str, Any]:
        """Provide AI-powered triage recommendation."""
        
        try:
            prompt = self.prompt_manager.render_template(
                "triage_recommendation",
                title=finding.title,
                severity=finding.severity.value,
                vuln_type=finding.vulnerability_type.value,
                url=str(finding.affected_url) if finding.affected_url else "N/A",
                description=finding.description,
                evidence=json.dumps(finding.evidence[:3])  # First 3 evidence items
            )
            
            schema = {
                "priority": "string",
                "business_impact": "string",
                "exploitability": "string",
                "false_positive_likelihood": "string",
                "verification_steps": ["string"],
                "remediation_urgency": "string",
                "recommendation": "string"
            }
            
            triage = await self.llm.generate_structured(prompt, schema)
            
            # Log triage
            audit_logger.log_security_event(
                "ai_triage_completed",
                f"AI triaged finding {finding.id}",
                finding_id=finding.id,
                priority=triage.get("priority", "unknown")
            )
            
            return triage
        
        except Exception as e:
            logger.error(f"Triage analysis failed: {e}")
            return {
                "priority": "medium",
                "business_impact": "Unknown",
                "exploitability": "Unknown",
                "false_positive_likelihood": "Unknown",
                "verification_steps": ["Manual review required"],
                "remediation_urgency": "Unknown",
                "recommendation": f"Manual triage required due to AI analysis failure: {e}"
            }


class ReconSummarizer:
    """AI-powered reconnaissance summarizer."""
    
    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm = llm_provider
        self.prompt_manager = PromptManager()
    
    async def summarize_recon(self, target: str, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize reconnaissance findings."""
        
        try:
            # Prepare recon data summary
            data_summary = self._prepare_recon_summary(recon_data)
            
            prompt = self.prompt_manager.render_template(
                "recon_summary",
                target=target,
                recon_data=data_summary
            )
            
            schema = {
                "key_findings": ["string"],
                "attack_surface": {
                    "domains": "number",
                    "subdomains": "number",
                    "open_ports": "number",
                    "web_applications": "number"
                },
                "high_priority_targets": ["string"],
                "next_steps": ["string"],
                "security_concerns": ["string"],
                "summary": "string"
            }
            
            summary = await self.llm.generate_structured(prompt, schema)
            
            # Log summarization
            audit_logger.log_security_event(
                "recon_summarized",
                f"AI summarized reconnaissance for {target}",
                target=target,
                findings_count=len(summary.get("key_findings", []))
            )
            
            return summary
        
        except Exception as e:
            logger.error(f"Recon summarization failed: {e}")
            return {
                "key_findings": ["Summarization failed"],
                "attack_surface": {"domains": 0, "subdomains": 0, "open_ports": 0, "web_applications": 0},
                "high_priority_targets": [],
                "next_steps": ["Manual analysis required"],
                "security_concerns": [],
                "summary": f"AI summarization failed: {e}"
            }
    
    def _prepare_recon_summary(self, recon_data: Dict[str, Any]) -> str:
        """Prepare a concise summary of recon data for the LLM."""
        summary_parts = []
        
        for collector, data in recon_data.get("results", {}).items():
            results = data.get("results", [])
            if results:
                summary_parts.append(f"{collector}: {len(results)} results")
                
                # Add sample results
                for result in results[:3]:  # First 3 results
                    if result.get("type") == "subdomain":
                        summary_parts.append(f"  - Subdomain: {result.get('domain')}")
                    elif result.get("type") == "host":
                        summary_parts.append(f"  - Host: {result.get('ip')} (ports: {result.get('port')})")
                    elif result.get("type") == "dns_record":
                        summary_parts.append(f"  - DNS: {result.get('record_type')} {result.get('value')}")
        
        return "\n".join(summary_parts)


# Global AI services
llm_provider = OpenAIProvider() if os.getenv("OPENAI_API_KEY") else None
embedding_service = EmbeddingService()
vulnerability_analyzer = VulnerabilityAnalyzer(llm_provider, embedding_service) if llm_provider else None
recon_summarizer = ReconSummarizer(llm_provider) if llm_provider else None


# Convenience functions
async def analyze_vulnerability(url: str, method: str, parameter: str, payload: str, response: str, status_code: int) -> Dict[str, Any]:
    """Analyze a potential vulnerability."""
    if vulnerability_analyzer:
        return await vulnerability_analyzer.analyze_potential_vulnerability(url, method, parameter, payload, response, status_code)
    else:
        return {"error": "LLM provider not configured"}


async def generate_finding_poc(finding: Finding) -> Dict[str, Any]:
    """Generate PoC for a finding."""
    if vulnerability_analyzer:
        return await vulnerability_analyzer.generate_poc(finding)
    else:
        return {"error": "LLM provider not configured"}


async def triage_finding_ai(finding: Finding) -> Dict[str, Any]:
    """Get AI triage recommendation."""
    if vulnerability_analyzer:
        return await vulnerability_analyzer.triage_finding(finding)
    else:
        return {"error": "LLM provider not configured"}


def encode_text_embedding(text: str) -> np.ndarray:
    """Generate embedding for text."""
    return embedding_service.encode_text(text)
