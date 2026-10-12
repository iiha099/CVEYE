{# Keyword heuristic for "AI / LLM related" CVEs, matched against the lower-cased
   description. It is a simple classifier, not ground truth: tune the list freely.
   If you change it, also change AI_PATTERN in dashboard/build_sample_marts.py. #}
{% macro ai_regex() -%}
\b(llm|llms|large language model|prompt injection|langchain|llama[ _-]?index|llama\.cpp|ollama|openai|chatgpt|hugging ?face|pytorch|tensorflow|keras|mlflow|gradio|vllm|onnx|machine learning|deep learning|neural network|artificial intelligence|generative ai|ai agent|ai assistant|copilot|model context protocol|mcp server|stable diffusion|autogpt|text-generation-webui)\b
{%- endmacro %}
