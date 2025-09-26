"""
API key management and rate limiting for external services.

This module provides secure storage and management of API keys for third-party
services like Shodan, Censys, VirusTotal, etc., along with rate limiting.
"""

import os
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
import redis
from threading import Lock


logger = logging.getLogger(__name__)


@dataclass
class APIKeyConfig:
    """Configuration for an API key."""
    service: str
    key: str
    rate_limit: int  # requests per minute
    daily_limit: Optional[int] = None  # requests per day
    enabled: bool = True
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class RateLimitStatus:
    """Current rate limit status for a service."""
    service: str
    requests_made: int
    requests_remaining: int
    reset_time: datetime
    daily_requests: int = 0
    daily_limit: Optional[int] = None


class APIKeyStore:
    """Secure storage for API keys with encryption."""
    
    def __init__(self, encryption_key: Optional[str] = None):
        """Initialize the API key store.
        
        Args:
            encryption_key: Base64-encoded encryption key. If None, will use
                          environment variable or generate a new one.
        """
        if encryption_key is None:
            encryption_key = os.getenv('API_ENCRYPTION_KEY')
            if encryption_key is None:
                # Generate a new key (should be saved securely)
                encryption_key = Fernet.generate_key().decode()
                logger.warning(
                    "Generated new encryption key. Save this securely: %s",
                    encryption_key
                )
        
        self.cipher = Fernet(encryption_key.encode())
        self.keys: Dict[str, APIKeyConfig] = {}
        self._load_keys()
    
    def add_key(self, config: APIKeyConfig) -> None:
        """Add or update an API key."""
        self.keys[config.service] = config
        self._save_keys()
        logger.info(f"Added API key for service: {config.service}")
    
    def get_key(self, service: str) -> Optional[str]:
        """Get decrypted API key for a service."""
        config = self.keys.get(service)
        if config and config.enabled:
            return config.key
        return None
    
    def get_config(self, service: str) -> Optional[APIKeyConfig]:
        """Get full configuration for a service."""
        return self.keys.get(service)
    
    def remove_key(self, service: str) -> bool:
        """Remove an API key."""
        if service in self.keys:
            del self.keys[service]
            self._save_keys()
            logger.info(f"Removed API key for service: {service}")
            return True
        return False
    
    def list_services(self) -> List[str]:
        """List all configured services."""
        return list(self.keys.keys())
    
    def enable_service(self, service: str) -> bool:
        """Enable a service."""
        if service in self.keys:
            self.keys[service].enabled = True
            self._save_keys()
            return True
        return False
    
    def disable_service(self, service: str) -> bool:
        """Disable a service."""
        if service in self.keys:
            self.keys[service].enabled = False
            self._save_keys()
            return True
        return False
    
    def _load_keys(self) -> None:
        """Load encrypted keys from storage."""
        keys_file = os.getenv('API_KEYS_FILE', 'config/api_keys.enc')
        
        if os.path.exists(keys_file):
            try:
                with open(keys_file, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self.cipher.decrypt(encrypted_data)
                keys_data = json.loads(decrypted_data.decode())
                
                for service, data in keys_data.items():
                    self.keys[service] = APIKeyConfig(**data)
                
                logger.info(f"Loaded {len(self.keys)} API keys")
                
            except Exception as e:
                logger.error(f"Failed to load API keys: {e}")
    
    def _save_keys(self) -> None:
        """Save encrypted keys to storage."""
        keys_file = os.getenv('API_KEYS_FILE', 'config/api_keys.enc')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(keys_file), exist_ok=True)
        
        try:
            # Convert to serializable format
            keys_data = {
                service: asdict(config) for service, config in self.keys.items()
            }
            
            json_data = json.dumps(keys_data).encode()
            encrypted_data = self.cipher.encrypt(json_data)
            
            with open(keys_file, 'wb') as f:
                f.write(encrypted_data)
            
            logger.debug("Saved API keys to encrypted storage")
            
        except Exception as e:
            logger.error(f"Failed to save API keys: {e}")


class RateLimiter:
    """Rate limiter for API requests."""
    
    def __init__(self, redis_url: Optional[str] = None):
        """Initialize the rate limiter.
        
        Args:
            redis_url: Redis connection URL. If None, uses environment variable
                      or defaults to localhost.
        """
        if redis_url is None:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/1')
        
        self.redis_client = redis.from_url(redis_url)
        self.local_cache: Dict[str, Dict] = {}
        self.cache_lock = Lock()
    
    def check_rate_limit(self, service: str, rate_limit: int, daily_limit: Optional[int] = None) -> RateLimitStatus:
        """Check if a request is allowed under rate limits.
        
        Args:
            service: Service name
            rate_limit: Requests per minute
            daily_limit: Optional daily request limit
            
        Returns:
            RateLimitStatus with current status
        """
        now = datetime.utcnow()
        minute_key = f"rate_limit:{service}:{now.strftime('%Y%m%d%H%M')}"
        day_key = f"daily_limit:{service}:{now.strftime('%Y%m%d')}"
        
        try:
            # Check minute-based rate limit
            current_minute_requests = self.redis_client.get(minute_key)
            current_minute_requests = int(current_minute_requests) if current_minute_requests else 0
            
            # Check daily limit if specified
            current_daily_requests = 0
            if daily_limit:
                current_daily_requests = self.redis_client.get(day_key)
                current_daily_requests = int(current_daily_requests) if current_daily_requests else 0
            
            # Calculate remaining requests
            minute_remaining = max(0, rate_limit - current_minute_requests)
            daily_remaining = max(0, daily_limit - current_daily_requests) if daily_limit else None
            
            # Determine actual remaining (limited by both minute and daily limits)
            if daily_remaining is not None:
                requests_remaining = min(minute_remaining, daily_remaining)
            else:
                requests_remaining = minute_remaining
            
            # Calculate reset time (next minute)
            reset_time = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
            
            return RateLimitStatus(
                service=service,
                requests_made=current_minute_requests,
                requests_remaining=requests_remaining,
                reset_time=reset_time,
                daily_requests=current_daily_requests,
                daily_limit=daily_limit
            )
            
        except Exception as e:
            logger.error(f"Failed to check rate limit for {service}: {e}")
            # Return conservative status on error
            return RateLimitStatus(
                service=service,
                requests_made=0,
                requests_remaining=0,
                reset_time=now + timedelta(minutes=1)
            )
    
    def consume_request(self, service: str, rate_limit: int, daily_limit: Optional[int] = None) -> bool:
        """Attempt to consume a request from the rate limit.
        
        Args:
            service: Service name
            rate_limit: Requests per minute
            daily_limit: Optional daily request limit
            
        Returns:
            True if request was allowed, False if rate limited
        """
        status = self.check_rate_limit(service, rate_limit, daily_limit)
        
        if status.requests_remaining <= 0:
            return False
        
        now = datetime.utcnow()
        minute_key = f"rate_limit:{service}:{now.strftime('%Y%m%d%H%M')}"
        day_key = f"daily_limit:{service}:{now.strftime('%Y%m%d')}"
        
        try:
            # Increment counters
            pipe = self.redis_client.pipeline()
            pipe.incr(minute_key)
            pipe.expire(minute_key, 60)  # Expire after 1 minute
            
            if daily_limit:
                pipe.incr(day_key)
                pipe.expire(day_key, 86400)  # Expire after 1 day
            
            pipe.execute()
            
            logger.debug(f"Consumed request for {service}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to consume request for {service}: {e}")
            return False
    
    def wait_for_rate_limit(self, service: str, rate_limit: int, daily_limit: Optional[int] = None) -> float:
        """Calculate how long to wait before next request is allowed.
        
        Returns:
            Seconds to wait (0 if request can be made immediately)
        """
        status = self.check_rate_limit(service, rate_limit, daily_limit)
        
        if status.requests_remaining > 0:
            return 0.0
        
        # Calculate time until reset
        now = datetime.utcnow()
        wait_time = (status.reset_time - now).total_seconds()
        return max(0.0, wait_time)
    
    def get_all_status(self, services: List[str], configs: Dict[str, APIKeyConfig]) -> Dict[str, RateLimitStatus]:
        """Get rate limit status for all services."""
        status_dict = {}
        
        for service in services:
            config = configs.get(service)
            if config:
                status_dict[service] = self.check_rate_limit(
                    service, config.rate_limit, config.daily_limit
                )
        
        return status_dict


class APIManager:
    """Combined API key and rate limit manager."""
    
    def __init__(self, encryption_key: Optional[str] = None, redis_url: Optional[str] = None):
        """Initialize the API manager."""
        self.key_store = APIKeyStore(encryption_key)
        self.rate_limiter = RateLimiter(redis_url)
        
        # Load default configurations
        self._load_default_configs()
    
    def make_request(self, service: str, request_func, *args, **kwargs) -> Any:
        """Make a rate-limited API request.
        
        Args:
            service: Service name
            request_func: Function to make the actual request
            *args, **kwargs: Arguments to pass to request_func
            
        Returns:
            Result of request_func or None if rate limited
        """
        config = self.key_store.get_config(service)
        if not config or not config.enabled:
            logger.warning(f"Service {service} not configured or disabled")
            return None
        
        # Check rate limit
        if not self.rate_limiter.consume_request(service, config.rate_limit, config.daily_limit):
            wait_time = self.rate_limiter.wait_for_rate_limit(service, config.rate_limit, config.daily_limit)
            logger.warning(f"Rate limited for {service}, need to wait {wait_time:.1f} seconds")
            return None
        
        try:
            # Add API key to request
            if 'api_key' not in kwargs:
                kwargs['api_key'] = config.key
            
            # Make the request
            result = request_func(*args, **kwargs)
            logger.debug(f"Successful API request to {service}")
            return result
            
        except Exception as e:
            logger.error(f"API request to {service} failed: {e}")
            raise
    
    def get_service_status(self, service: str) -> Dict[str, Any]:
        """Get comprehensive status for a service."""
        config = self.key_store.get_config(service)
        if not config:
            return {'configured': False}
        
        rate_status = self.rate_limiter.check_rate_limit(
            service, config.rate_limit, config.daily_limit
        )
        
        return {
            'configured': True,
            'enabled': config.enabled,
            'rate_limit': config.rate_limit,
            'daily_limit': config.daily_limit,
            'requests_remaining': rate_status.requests_remaining,
            'daily_requests': rate_status.daily_requests,
            'reset_time': rate_status.reset_time.isoformat()
        }
    
    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status for all configured services."""
        services = self.key_store.list_services()
        return {service: self.get_service_status(service) for service in services}
    
    def _load_default_configs(self) -> None:
        """Load default API configurations from environment."""
        default_configs = [
            # Shodan
            {
                'service': 'shodan',
                'env_var': 'SHODAN_API_KEY',
                'rate_limit': 100,  # requests per minute
                'daily_limit': None
            },
            # Censys
            {
                'service': 'censys',
                'env_var': 'CENSYS_API_KEY',
                'rate_limit': 120,
                'daily_limit': None
            },
            # VirusTotal
            {
                'service': 'virustotal',
                'env_var': 'VIRUSTOTAL_API_KEY',
                'rate_limit': 4,  # Free tier limit
                'daily_limit': 1000
            },
            # SecurityTrails
            {
                'service': 'securitytrails',
                'env_var': 'SECURITYTRAILS_API_KEY',
                'rate_limit': 50,
                'daily_limit': 2000
            },
            # Crunchbase
            {
                'service': 'crunchbase',
                'env_var': 'CRUNCHBASE_API_KEY',
                'rate_limit': 200,
                'daily_limit': None
            },
            # GitHub
            {
                'service': 'github',
                'env_var': 'GITHUB_TOKEN',
                'rate_limit': 5000,  # Per hour, but we'll use per minute
                'daily_limit': None
            }
        ]
        
        for config_data in default_configs:
            api_key = os.getenv(config_data['env_var'])
            if api_key and config_data['service'] not in self.key_store.keys:
                config = APIKeyConfig(
                    service=config_data['service'],
                    key=api_key,
                    rate_limit=config_data['rate_limit'],
                    daily_limit=config_data.get('daily_limit'),
                    enabled=True,
                    metadata={'source': 'environment'}
                )
                self.key_store.add_key(config)


# Global API manager instance
api_manager = APIManager()


# Convenience functions
def get_api_key(service: str) -> Optional[str]:
    """Get API key for a service."""
    return api_manager.key_store.get_key(service)


def make_api_request(service: str, request_func, *args, **kwargs) -> Any:
    """Make a rate-limited API request."""
    return api_manager.make_request(service, request_func, *args, **kwargs)


def check_service_status(service: str) -> Dict[str, Any]:
    """Check status of a service."""
    return api_manager.get_service_status(service)
