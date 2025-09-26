import os

class Config:
    # Basic Flask settings
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    
    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOGGING_CONFIG = {
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'logs/app.log'
    }
    
    # Analysis modules - UPDATED with typosquatting
    ANALYSIS_CONFIG = {
        'dns': {'enabled': True},
        'headers': {'enabled': True},
        'ssl': {'enabled': True},
        'metadata': {'enabled': True},
        'typosquatting': {'enabled': True}  # ADDED
    }
    
    # Risk thresholds - UPDATED with very_low
    RISK_THRESHOLDS = {
        'very_low': 0.0,   # ADDED
        'low': 0.2,
        'medium': 0.5,
        'high': 0.75
    }
    
    # Model weights
    ML_WEIGHT = 0.4
    HEURISTIC_WEIGHT = 0.6
    
    # Caching
    CACHE_ENABLED = True
    CACHE_TIMEOUT = 300  # 5 minutes
    CACHE_MAX_SIZE = 1000
    
    # Typosquatting-specific weights - ADDED
    TYPOSQUATTING_WEIGHTS = {
        'homoglyph_detected': 25,
        'typosquatting_detected': 30,
        'high_similarity': 20,
        'unusual_length': 10
    }
    
    @classmethod
    def validate_config(cls):
        """Validate configuration"""
        errors = []
        warnings = []
        
        if cls.ML_WEIGHT + cls.HEURISTIC_WEIGHT != 1.0:
            warnings.append("Model weights don't sum to 1.0")
            
        return {'errors': errors, 'warnings': warnings}

current_config = Config()