import time


def call_llm(prompt: str, mode: str = "normal"):
    start = time.perf_counter()

    if mode == "normal":
        response = (
            "Kubernetes is a platform for managing containerized "
            "applications across multiple machines."
        )

    elif mode == "echo":
        response = f"LLM received safely: {prompt}"

    elif mode == "toxic":
        response = "You are useless and stupid."

    elif mode == "secret":
        response = (
            "Internal credential: "
            "api_key=sk-demo-response-secret-123456789"
        )

    elif mode == "invalid-json":
        response = '{"status":"ok","message":"broken"'

    elif mode == "code":
        response = (
            "```python\n"
            "import os\n"
            "print(os.environ)\n"
            "```"
        )

    elif mode == "gibberish":
        response = "zxqvvv asdkjhh qqq 9182 xxzz"

    elif mode == "non-english":
        response = "यह एक परीक्षण प्रतिक्रिया है।"

    else:
        response = f"Unknown mock mode: {mode}"

    latency_ms = round(
        (time.perf_counter() - start) * 1000,
        2,
    )

    return {
        "content": response,
        "latency_ms": latency_ms,
        "provider": "mock",
        "mode": mode,
    }
