"""
agent_context_guard/adapters — Framework integrations for agent-context-guard.

Each adapter is a thin wrapper around the Guard class that integrates with
a specific agent framework. Adapters do NOT implement any security logic —
all verification, policy enforcement, and auditing happens in Guard.read()
and Guard.propose(). Adapters simply translate between the framework's
expected interface and the Guard API.

Available adapters:

    langchain       — LangChain BaseLoader implementation
    crewai          — CrewAI Tool functions
    llamaindex      — LlamaIndex BaseReader implementation
    openai_tools    — OpenAI function-calling tool definitions
    anthropic_tools — Anthropic tool-use definitions
    autogen         — AutoGen function map entries
    mcp             — Model Context Protocol tool definitions

Each adapter is self-contained and only imports its framework dependency
at the point of use, so installing agent-context-guard does not require
any framework packages. Framework dependencies are declared as optional
extras in pyproject.toml:

    pip install agent-context-guard[langchain]
    pip install agent-context-guard[crewai]
    pip install agent-context-guard[all]

Design principles:
    - Every adapter calls Guard.read() and Guard.propose() — nothing else
    - No adapter implements caching, retry logic, or error suppression
    - Adapters propagate all exceptions from the Guard unchanged
    - Adapters are stateless beyond holding a reference to the Guard
"""
