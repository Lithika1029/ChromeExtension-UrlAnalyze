# models/model_util.py - CORRECTED WITH PROPER PATH HANDLING AND MISSING METHODS
import joblib
import numpy as np
import pandas as pd
import logging
from pathlib import Path
import re
import os

class ModelManager:
    def __init__(self, models_dir='modals'):
        self.models_dir = Path(models_dir)
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.logger = logging.getLogger(__name__)
        self.load_available_model()
    
    def find_model_files(self):
        """Search for any available model files in all subdirectories"""
        model_files = {}
        
        # Check multiple possible locations
        possible_locations = [
            Path('modals/saved_models'),  # Your actual structure
            Path('modals'),               # Root modals directory
            Path('saved_models'),         # Common location
            Path('models'),               # Another common location
        ]
        
        for location in possible_locations:
            if location.exists():
                self.logger.info(f"🔍 Searching in {location}")
                
                # Search for .pkl files recursively
                pkl_files = list(location.rglob('*.pkl'))
                if pkl_files:
                    for file in pkl_files:
                        filename = file.name.lower()
                        file_path_str = str(file)
                        
                        # Comprehensive model package
                        if 'comprehensive' in filename:
                            model_files['comprehensive_model'] = file
                        # Your specific tuned model
                        elif 'tuned' in filename and 'gradient' in filename:
                            model_files['specific_model'] = file
                        elif 'gradient' in filename and 'boosting' in filename:
                            model_files['specific_model'] = file
                        # Scaler files
                        elif 'scaler' in filename:
                            model_files['scaler'] = file
                        # Feature files
                        elif 'feature' in filename or 'selected' in filename:
                            model_files['features'] = file
                        # Generic model files
                        elif 'model' in filename and 'comprehensive' not in filename:
                            model_files['generic_model'] = file
                
                # Also check for non-.pkl model files or other patterns
                all_files = list(location.rglob('*'))
                for file in all_files:
                    if file.is_file():
                        filename = file.name.lower()
                        if any(term in filename for term in ['model', 'scaler', 'feature']):
                            if file not in pkl_files:  # If not already found
                                self.logger.info(f"Found potential model file: {file}")
        
        self.logger.info(f"Found model files: {list(model_files.keys())}")
        return model_files
    
    def load_available_model(self):
        """Load any available model with comprehensive search"""
        try:
            model_files = self.find_model_files()
            
            if not model_files:
                self.logger.error("No model files found in any location!")
                self._create_fallback_model()
                return
            
            # Strategy 1: Try to load from modals/saved_models/ first
            saved_models_path = Path('modals/saved_models')
            if saved_models_path.exists():
                self.logger.info("Attempting to load from modals/saved_models/")
                
                # Look for comprehensive model package
                comprehensive_path = saved_models_path / 'comprehensive_gb_model.pkl'
                if comprehensive_path.exists():
                    try:
                        model_package = joblib.load(comprehensive_path)
                        if isinstance(model_package, dict) and 'model' in model_package:
                            self.model = model_package['model']
                            self.feature_names = model_package.get('feature_names', [])
                            self.scaler = model_package.get('scaler', None)
                            self.logger.info(f"✅ Loaded comprehensive model with {len(self.feature_names)} features")
                            return
                    except Exception as e:
                        self.logger.warning(f"Failed to load comprehensive model: {e}")
                
                # Try individual components
                model_paths = {
                    'model': saved_models_path / 'gb_model.pkl',
                    'scaler': saved_models_path / 'scaler.pkl', 
                    'features': saved_models_path / 'feature_names.pkl'
                }
                
                if all(path.exists() for path in model_paths.values()):
                    try:
                        self.model = joblib.load(model_paths['model'])
                        self.scaler = joblib.load(model_paths['scaler'])
                        self.feature_names = joblib.load(model_paths['features'])
                        self.logger.info(f"✅ Loaded individual models with {len(self.feature_names)} features")
                        return
                    except Exception as e:
                        self.logger.warning(f"Failed to load individual models: {e}")
            
            # Strategy 2: Try loading from any found files
            if 'comprehensive_model' in model_files:
                try:
                    model_package = joblib.load(model_files['comprehensive_model'])
                    if isinstance(model_package, dict) and 'model' in model_package:
                        self.model = model_package['model']
                        self.feature_names = model_package.get('feature_names', [])
                        self.scaler = model_package.get('scaler', None)
                        self.logger.info(f"✅ Loaded comprehensive model package")
                        return
                except Exception as e:
                    self.logger.warning(f"Failed to load comprehensive model package: {e}")
            
            # Strategy 3: Try to load specific components from any location
            components_loaded = 0
            if 'specific_model' in model_files or 'generic_model' in model_files:
                model_file = model_files.get('specific_model') or model_files.get('generic_model')
                try:
                    self.model = joblib.load(model_file)
                    components_loaded += 1
                    self.logger.info("✅ Loaded model component")
                except Exception as e:
                    self.logger.warning(f"Failed to load model: {e}")
            
            if 'scaler' in model_files:
                try:
                    self.scaler = joblib.load(model_files['scaler'])
                    components_loaded += 1
                    self.logger.info("✅ Loaded scaler component")
                except Exception as e:
                    self.logger.warning(f"Failed to load scaler: {e}")
            
            if 'features' in model_files:
                try:
                    self.feature_names = joblib.load(model_files['features'])
                    components_loaded += 1
                    self.logger.info("✅ Loaded features component")
                except Exception as e:
                    self.logger.warning(f"Failed to load features: {e}")
            
            if components_loaded >= 2:  # At least model + one other component
                self.logger.info(f"✅ Successfully loaded {components_loaded} components")
                return
            
            # If we reach here, no model was successfully loaded
            raise Exception("No usable model files could be loaded")
                
        except Exception as e:
            self.logger.error(f"❌ Error loading available model: {e}")
            self._create_fallback_model()
    
    def _create_fallback_model(self):
        """Create a simple fallback model"""
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        # Train on minimal dummy data
        X_dummy = np.random.rand(10, 5)
        y_dummy = np.random.randint(0, 2, 10)
        self.model.fit(X_dummy, y_dummy)
        self.feature_names = ['url_length', 'domain_length', 'is_https', 'suspicious_keyword_count']
        self.scaler = None
        self.logger.warning("⚠️ Using fallback model")
    
    def _extract_compatible_features(self, features):
        """Extract features that match our trained model's feature names"""
        compatible_features = {}
        
        # Map feature names from Flask app to our model's expected features
        feature_mapping = self._create_feature_mapping()
        
        for expected_feature in self.feature_names:
            value_found = False
            
            # Try exact match first
            if expected_feature in features:
                compatible_features[expected_feature] = features[expected_feature]
                value_found = True
            else:
                # Try mapped names
                for flask_feature, model_feature in feature_mapping.items():
                    if model_feature == expected_feature and flask_feature in features:
                        compatible_features[expected_feature] = features[flask_feature]
                        value_found = True
                        break
            
            # If not found, use default value
            if not value_found:
                compatible_features[expected_feature] = self._get_default_value(expected_feature)
                self.logger.debug(f"Using default value for feature: {expected_feature}")
        
        return compatible_features
    
    def _create_feature_mapping(self):
        """Create mapping between Flask app features and model features"""
        mapping = {
            # URL features mapping
            'url_url_length': 'url_length',
            'url_domain_length': 'domain_length',
            'url_has_https': 'is_https',
            'url_subdomain_count': 'subdomain_count',
            'url_has_ip': 'has_ip_address',
            'url_entropy': 'url_entropy',
            
            # Security features mapping
            'url_suspicious_keywords': 'suspicious_keyword_count',
            'url_is_shortened': 'is_shortened',
            'url_suspicious_tld': 'suspicious_tld',
            
            # Lexical features mapping
            'url_digit_ratio': 'digit_ratio',
            'url_letter_ratio': 'letter_ratio',
            'url_special_char_ratio': 'special_char_ratio',
        }
        return mapping
    
    def _get_default_value(self, feature_name):
        """Get sensible default values for features"""
        defaults = {
            'url_length': 0, 'domain_length': 0, 'is_https': 0, 'subdomain_count': 0,
            'has_ip_address': 0, 'suspicious_keyword_count': 0, 'is_shortened': 0,
            'suspicious_tld': 0, 'digit_ratio': 0, 'letter_ratio': 0, 'special_char_ratio': 0,
            'entropy': 0, 'path_length': 0, 'query_length': 0, 'param_count': 0
        }
        
        for key, value in defaults.items():
            if key in feature_name.lower():
                return value
        return 0
    
    def _preprocess_features(self, features_dict):
        """Preprocess features to match model expectations"""
        try:
            # Extract compatible features
            compatible_features = self._extract_compatible_features(features_dict)
            
            # Create feature vector in correct order
            feature_vector = self._create_feature_vector(compatible_features)
            
            # Apply scaling if scaler is available
            if self.scaler is not None:
                feature_df = pd.DataFrame(feature_vector, columns=self.feature_names)
                feature_vector = self.scaler.transform(feature_df)  
                          
            return feature_vector
            
        except Exception as e:
            self.logger.error(f"Error preprocessing features: {e}")
            # Return a zero vector of appropriate length
            feature_length = len(self.feature_names) if self.feature_names else 10
            return np.zeros((1, feature_length))
    
    def _create_feature_vector(self, features_dict):
        """Create feature vector in correct order based on feature_names"""
        try:
            if not self.feature_names:
                self.logger.warning("No feature names available, using fallback")
                return np.zeros((1, 10))
            
            feature_vector = []
            for feature_name in self.feature_names:
                value = features_dict.get(feature_name, 0.0)
                # Ensure numeric value
                try:
                    numeric_value = float(value)
                except (ValueError, TypeError):
                    numeric_value = 0.0
                feature_vector.append(numeric_value)
            
            return np.array(feature_vector).reshape(1, -1)
            
        except Exception as e:
            self.logger.error(f"Error creating feature vector: {e}")
            return np.zeros((1, len(self.feature_names) if self.feature_names else 10))
    
    def predict(self, features_dict):
        """Make prediction using the loaded model"""
        try:
            if self.model is None:
                self.logger.error("No model available for prediction")
                return {
                    'prediction': 0,
                    'probability': 0.5,
                    'confidence': 0.0,
                    'error': 'Model not loaded'
                }
            
            # Preprocess features
            feature_vector = self._preprocess_features(features_dict)
            
            # Make prediction
            prediction = self.model.predict(feature_vector)[0]
            
            # Get probabilities if available
            try:
                probabilities = self.model.predict_proba(feature_vector)[0]
                probability = float(probabilities[1])  # Probability of class 1 (phishing)
            except (AttributeError, IndexError):
                # Fallback if predict_proba is not available
                probability = float(prediction)
            
            confidence = abs(probability - 0.5) * 2  # Convert to 0-1 confidence scale
            
            return {
                'prediction': int(prediction),
                'probability': float(probability),
                'confidence': float(confidence),
                'feature_vector_shape': feature_vector.shape
            }
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return {
                'prediction': 0,
                'probability': 0.5,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def health_check(self):
        """Check model health"""
        status = 'healthy' if self.model is not None else 'degraded'
        model_type = 'comprehensive' if len(self.feature_names) > 10 else 'fallback'
        
        return {
            'status': status,
            'model_type': model_type,
            'features_loaded': len(self.feature_names),
            'scaler_available': self.scaler is not None,
            'model_ready': self.model is not None
        }

# Singleton instance
_model_manager = None

def get_model_manager():
    global _model_manager
    if _model_manager is None:
        _model_manager = ModelManager()
    return _model_manager