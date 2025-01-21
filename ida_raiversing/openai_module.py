import json
import logging
import os
from typing import Dict, List, Optional, Set
import openai
from pathlib import Path
from dotenv import load_dotenv

from .ai_interface import AIInterface

class OpenAIModule(AIInterface):
    def __init__(self, api_key_path: str = None, model: str = "gpt-4-1106-preview"):
        """Initialize OpenAI module."""
        self.model = model
        self.logger = logging.getLogger("OpenAIModule")
        
        # Try to load API key from various sources
        load_dotenv()
        
        if api_key_path and Path(api_key_path).exists():
            openai.api_key = Path(api_key_path).read_text().strip()
        elif os.getenv("OPENAI_API_KEY"):
            openai.api_key = os.getenv("OPENAI_API_KEY")
        else:
            raise ValueError("No OpenAI API key found. Please provide it via file or OPENAI_API_KEY environment variable")
        
    def get_max_tokens(self) -> int:
        """Return max tokens for current model."""
        model_limits = {
            "gpt-3.5-turbo": 4096,
            "gpt-3.5-turbo-16k": 16384,
            "gpt-4": 8192,
            "gpt-4-32k": 32768,
            "gpt-4-1106-preview": 128000
        }
        return model_limits.get(self.model, 4096)
        
    def analyze_function(self, code: str, context: Dict) -> Optional[Dict]:
        """Analyze a single function using OpenAI."""
        return self.analyze_functions([{"code": code, "context": context}])[0]
        
    def analyze_functions(self, functions: List[Dict]) -> List[Optional[Dict]]:
        """Analyze multiple functions together for better context."""
        try:
            # Construct prompt for all functions
            prompt = self._build_batch_prompt(functions)
            
            # Call OpenAI API
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=4000,  # Increased for batch analysis
                top_p=0.95,
                frequency_penalty=0.0,
                presence_penalty=0.0
            )
            
            # Parse response
            content = response.choices[0].message.content
            try:
                result = json.loads(content)
                if not isinstance(result, list):
                    result = [result]  # Handle single function response
                return [self._validate_response(r) for r in result]
            except json.JSONDecodeError:
                self.logger.error(f"Failed to parse response as JSON: {content}")
                return [None] * len(functions)
                
        except Exception as e:
            self.logger.error(f"Error calling OpenAI API: {str(e)}")
            return [None] * len(functions)
            
    def _get_system_prompt(self) -> str:
        """Return the system prompt for the AI."""
        return """You are an expert reverse engineer analyzing decompiled code.
Your task is to understand the functions' purposes and suggest better names for the functions and their variables.
You have deep knowledge of:
1. Common programming patterns and idioms
2. Standard library functions across multiple languages
3. Common algorithms and data structures
4. System calls and APIs
5. Security-related functions and patterns

When analyzing multiple functions together:
- Look for relationships and patterns between functions
- Identify common purposes or categories
- Ensure consistent naming across related functions
- Consider how functions work together
- Identify potential library or algorithm implementations

Respond with a JSON array containing analysis for each function.
Focus on accuracy and clarity in your naming suggestions.
Be especially attentive to:
- Security-relevant functions (crypto, authentication, etc.)
- Standard library equivalents
- Common programming patterns
- Data structure operations
- Mathematical operations
- Relationships between functions"""
        
    def _build_batch_prompt(self, functions: List[Dict]) -> str:
        """Build prompt for analyzing multiple functions."""
        prompt = "Analyze these decompiled functions and their relationships:\n\n"
        
        for i, func in enumerate(functions, 1):
            code = func["code"]
            context = func["context"]
            
            prompt += f"""Function {i}:
Code:
{code}

Context:
- Called by: {', '.join(context.get('called_by', []))}
- Calls: {', '.join(context.get('calls', []))}
- Data references: {', '.join(context.get('data_refs', []))}
- Strings used: {', '.join(context.get('strings', []))}
- Constants: {', '.join(map(str, context.get('constants', [])))}
- Structure references: {', '.join(context.get('struct_refs', []))}

"""
        
        prompt += """Analyze these functions together, considering:
1. Each function's individual purpose
2. Relationships between functions
3. Common patterns or algorithms
4. Shared data structures or resources
5. Security implications
6. Standard library equivalents

Respond with a JSON array containing for each function:
1. "renames": mapping of original names to better names
2. "description": brief description of function purpose
3. "confidence": confidence score (0.0-1.0) in your analysis
4. "category": function category (e.g., "crypto", "data_structure", "io", "math", etc.)
5. "security_relevant": boolean indicating if the function is security-relevant
6. "relationships": list of relationships with other functions in the batch
7. "shared_purpose": any common purpose with other functions"""
        
        return prompt
        
    def _validate_response(self, response: Dict) -> Optional[Dict]:
        """Validate and clean up the AI response."""
        required_keys = {"renames", "description", "confidence"}
        if not all(key in response for key in required_keys):
            return None
            
        if not isinstance(response["renames"], dict):
            return None
            
        if not isinstance(response["confidence"], (int, float)):
            return None
            
        # Add optional fields if not present
        response.setdefault("category", "unknown")
        response.setdefault("security_relevant", False)
        response.setdefault("relationships", [])
        response.setdefault("shared_purpose", None)
            
        return response 