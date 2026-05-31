from splunkology.eval.orchestrators.base import BaseOrchestrator, OrchestratorResult
from splunkology.eval.orchestrators.claude_code_adapter import ClaudeCodeAdapter

try:
    from splunkology.eval.orchestrators.gemini_adapter import GeminiAdapter
except ImportError:
    GeminiAdapter = None

try:
    from splunkology.eval.orchestrators.langgraph_adapter import LangGraphAdapter
except ImportError:
    LangGraphAdapter = None

try:
    from splunkology.eval.orchestrators.native_loop import NativeLoopAdapter
except ImportError:
    NativeLoopAdapter = None

try:
    from splunkology.eval.orchestrators.openai_fc_adapter import OpenAIFunctionCallingAdapter
except ImportError:
    OpenAIFunctionCallingAdapter = None

REGISTRY: dict[str, type[BaseOrchestrator]] = {
    k: v
    for k, v in {
        "splunkology-claudecode": ClaudeCodeAdapter,
        "splunkology-gemini3pro": GeminiAdapter,
        "splunkology-langgraph": LangGraphAdapter,
        "splunkology-native": NativeLoopAdapter,
        "splunkology-openai-fc": OpenAIFunctionCallingAdapter,
    }.items()
    if v is not None
}

__all__ = [
    "REGISTRY",
    "BaseOrchestrator",
    "ClaudeCodeAdapter",
    "GeminiAdapter",
    "LangGraphAdapter",
    "NativeLoopAdapter",
    "OpenAIFunctionCallingAdapter",
    "OrchestratorResult",
]
