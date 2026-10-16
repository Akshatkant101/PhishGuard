from pathlib import Path
import logging
from typing import Dict, List, Optional
import joblib
import numpy as np
import pandas as pd
import shap
from app.config import settings
from app.services.feature_extractor import get_feature_description
from app.services.ml_model import ml_service
from app.schemas.schemas import ReasonItem

logger = logging.getLogger(__name__)


class ExplainerService:
    def __init__(self):
        self.tree_explainer: Optional[shap.TreeExplainer] = None
        self._init_explainer()

    def _init_explainer(self):
        try:
            model_dir = Path(settings.MODEL_DIR)
            xgb_path = model_dir / "xgb_base.joblib"
            if xgb_path.exists():
                xgb_model = joblib.load(xgb_path)
                self.tree_explainer = shap.TreeExplainer(xgb_model)
                logger.info("Initialized real SHAP TreeExplainer on XGBoost base model.")
            elif ml_service.is_loaded and hasattr(ml_service.model, "estimator"):
                # Handle single estimator inside calibration wrapper if available
                self.tree_explainer = shap.TreeExplainer(ml_service.model.estimator)
                logger.info("Initialized real SHAP TreeExplainer from calibrated estimator.")
        except Exception as e:
            logger.warning(f"Could not initialize TreeExplainer, fallback active: {e}")

    def explain(self, features: Dict[str, float], top_k: int = 5) -> List[ReasonItem]:
        """Explain the model prediction for a URL using real SHAP TreeExplainer.

        Returns top_k reasons sorted by absolute SHAP impact magnitude.
        """
        if self.tree_explainer is None:
            self._init_explainer()

        feature_names = ml_service.feature_names or list(features.keys())
        reasons: List[ReasonItem] = []

        if self.tree_explainer is not None:
            try:
                # Prepare single-row DataFrame
                row = [features.get(c, 0.0) for c in feature_names]
                X_df = pd.DataFrame([row], columns=feature_names)

                # Compute exact Tree SHAP values
                shap_values = self.tree_explainer.shap_values(X_df)
                if isinstance(shap_values, list):
                    shap_row = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
                elif len(shap_values.shape) == 2:
                    shap_row = shap_values[0]
                else:
                    shap_row = shap_values

                indexed_shap = sorted(enumerate(shap_row), key=lambda x: abs(x[1]), reverse=True)

                for idx, impact in indexed_shap:
                    feat_name = feature_names[idx]
                    feat_val = float(features.get(feat_name, 0.0))

                    # Filter out zero-impact or zero-value inactive features
                    if abs(impact) < 0.0001 and feat_val == 0.0:
                        continue

                    direction = "suspicious" if impact > 0 else "benign"
                    desc = self._format_reason(feat_name, feat_val, direction)

                    reasons.append(
                        ReasonItem(
                            feature=feat_name,
                            description=desc,
                            value=round(feat_val, 4),
                            impact=round(float(impact), 4),
                            direction=direction,
                        )
                    )
                    if len(reasons) >= top_k:
                        break
            except Exception as e:
                logger.error(f"Error computing SHAP values: {e}", exc_info=True)

        # Fallback heuristic if SHAP computation failed or produced no output
        if not reasons:
            reasons = self._heuristic_reasons(features, top_k)

        return reasons

    def _format_reason(self, feature: str, value: float, direction: str) -> str:
        """Create intuitive, natural explanations matching direction and value."""
        is_susp = direction == "suspicious"

        if feature == "is_https":
            return "Missing HTTPS encryption; uses unencrypted plain HTTP protocol" if value == 0 else "Protected by secure HTTPS encryption"
        elif feature == "url_digit_ratio":
            return f"Elevated numeric ratio in URL ({value*100:.1f}% digits) typical of generated phishing paths" if is_susp else f"Low numeric ratio in URL ({value*100:.1f}% digits)"
        elif feature == "subdomain_count":
            if is_susp:
                return f"Excessive subdomain nesting ({int(value)} subdomains) obscuring the actual root domain" if value >= 2 else f"Contains {int(value)} subdomain(s) creating atypical domain hierarchy"
            return f"Standard clean domain structure with {int(value)} subdomain(s)"
        elif feature == "path_hyphen_ratio":
            return f"High concentration of hyphens in URL path ({value*100:.1f}%)" if is_susp else f"Normal path hyphen ratio ({value*100:.1f}%)"
        elif feature == "domain_length":
            if is_susp:
                return f"Unusually long domain name ({int(value)} characters) often used to mimic complex enterprise names" if value > 25 else f"Short throwaway domain name ({int(value)} characters)"
            return f"Standard domain length ({int(value)} characters)"
        elif feature == "domain_dot_count":
            return f"Elevated dot count in domain ({int(value)} dots), characteristic of multi-layered lookalike hosts" if is_susp else f"Standard dot count in domain ({int(value)} dot(s))"
        elif feature == "domain_hyphen_count":
            return f"Domain contains {int(value)} hyphen(s), typical of brand typosquatting" if is_susp else f"Domain contains no suspicious hyphens ({int(value)} hyphens)"
        elif feature == "path_digit_ratio":
            return f"High numeric density in path ({value*100:.1f}% digits), typical of tracking tokens in phishing kits" if is_susp else f"Standard low digit ratio in path ({value*100:.1f}%)"
        elif feature == "hostname_length":
            return f"Long hostname length ({int(value)} characters) exceeding typical web standards" if is_susp else f"Standard hostname length ({int(value)} characters)"
        elif feature == "path_has_suspicious_ext":
            return "URL path explicitly points to an executable or script extension (.exe, .php, .cgi)" if value > 0 else "URL path does not target executable or suspicious file types"
        elif feature == "has_at_symbol":
            return "URL contains '@' symbol which can redirect browser credentials" if value > 0 else "URL does not contain '@' credential redirect tokens"
        elif feature == "brand_impersonation":
            return "Target brand keyword detected in subdomain while primary domain is completely different" if value > 0 else "No brand impersonation detected in subdomain"
        elif feature == "brand_in_subdomain":
            return "Brand name masquerading inside subdomain" if value > 0 else "No brand keywords in subdomain"
        elif feature == "brand_in_domain":
            return "Brand name observed inside domain structure" if is_susp else "Domain matches recognized organization brand name"
        elif feature == "suspicious_tld":
            return "Uses a top-level domain frequently associated with abuse (.xyz, .top, .tk, etc.)" if value > 0 else "Uses an established, standard top-level domain"
        elif feature == "domain_entropy":
            return f"High domain character randomness ({value:.2f} entropy bits), indicative of algorithmic generation (DGA)" if is_susp else f"Natural language domain entropy ({value:.2f} bits)"
        elif feature == "domain_digit_count":
            return f"Domain contains {int(value)} digits, characteristic of disposable domains" if is_susp else f"Clean domain name without excessive numbers ({int(value)} digits)"
        elif feature == "domain_digit_ratio":
            return f"Elevated proportion of digits in domain ({value*100:.1f}%)" if is_susp else f"Low numeric density in domain ({value*100:.1f}%)"
        elif feature == "tld_length":
            return f"Unusual top-level domain length ({int(value)} characters)" if is_susp else f"Standard TLD length ({int(value)} characters)"
        elif feature == "path_depth":
            return f"Deep directory nesting ({int(value)} path levels)" if is_susp else f"Shallow path depth ({int(value)} path levels)"
        elif feature == "query_param_count":
            return f"Excessive query parameters ({int(value)} parameters) often used for phishing session IDs" if is_susp else f"Standard query parameter count ({int(value)} parameter(s))"
        elif feature == "has_ip_address":
            return "Uses raw IP address directly instead of a registered domain name (high risk)" if value > 0 else "Uses a registered domain name rather than an IP address"
        elif feature == "has_double_slash_redirect":
            return "Contains '//' sequence in path used for open redirects" if value > 0 else "No redirect sequences in path"
        elif feature == "has_punycode":
            return "Punycode (xn--) detected, often used in homograph lookalike attacks" if value > 0 else "Standard ASCII domain encoding without homograph punycode"
        elif feature == "is_shortened":
            return "Uses a URL shortener service masking true destination" if value > 0 else "Direct URL without shortening service"
        elif feature == "url_special_char_ratio":
            return f"Elevated special character ratio in URL structure ({value*100:.1f}%)" if is_susp else f"Normal special character ratio in URL ({value*100:.1f}%)"

        base_desc = get_feature_description(feature)
        return f"{base_desc} (value: {value:.2f}) indicates {direction} behavior"

    def _heuristic_reasons(self, features: Dict[str, float], top_k: int) -> List[ReasonItem]:
        """Rule-based explanations when ML model attribution is uninitialized."""
        heuristics = []
        if features.get("has_ip_address", 0) > 0:
            heuristics.append(("has_ip_address", "Uses an IP address directly instead of a domain name", 1.0, 2.5, "suspicious"))
        if features.get("brand_impersonation", 0) > 0:
            heuristics.append(("brand_impersonation", "Brand name appears in subdomain while domain is different", 1.0, 3.0, "suspicious"))
        if features.get("suspicious_tld", 0) > 0:
            heuristics.append(("suspicious_tld", "Uses a top-level domain frequently abused in scams", 1.0, 1.8, "suspicious"))
        if features.get("is_https", 0) == 0:
            heuristics.append(("is_https", "Missing HTTPS encryption", 0.0, 1.2, "suspicious"))
        else:
            heuristics.append(("is_https", "Protected by HTTPS encryption", 1.0, -1.2, "benign"))

        return [
            ReasonItem(
                feature=h[0],
                description=h[1],
                value=h[2],
                impact=h[3],
                direction=h[4],
            )
            for h in heuristics[:top_k]
        ]


explainer_service = ExplainerService()
