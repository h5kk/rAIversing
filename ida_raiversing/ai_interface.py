from abc import ABC, abstractmethod
from typing import Dict, Optional

class AIInterface(ABC):
    """Abstract base class for AI model interfaces."""
    
    @abstractmethod
    def get_max_tokens(self) -> int:
        """Return the maximum number of tokens the model can process."""
        pass
        
    @abstractmethod
    def analyze_function(self, code: str, context: Dict) -> Optional[Dict]:
        """
        Analyze a function and return suggestions for improvement.
        
        Args:
            code: The decompiled function code
            context: Additional context about the function
            
        Returns:
            Dict containing suggestions, or None if no improvements found:
            {
                "renames": {
                    "old_name": "new_name",
                    "old_param": "new_param",
                    ...
                },
                "description": "Function description",
                "confidence": float
            }
        """
        pass 