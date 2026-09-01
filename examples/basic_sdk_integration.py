import os

from accuknox_llm_defense import LLMDefenseClient


def main() -> None:
    client = LLMDefenseClient(
        llm_defense_api_key=os.environ["ACCUKNOX_PF_TOKEN"],
        user_info=os.environ.get(
            "PF_USER_INFO",
            "prompt-firewall-sdk-example",
        ),
    )

    prompt = "Explain Kubernetes in one sentence."
    prompt_result = client.scan_prompt(content=prompt)
    sanitized_prompt = prompt_result.get("sanitized_content", prompt)
    session_id = prompt_result.get("session_id")

    model_response = "Kubernetes manages containerized workloads."
    response_result = client.scan_response(
        content=model_response,
        prompt=sanitized_prompt,
        session_id=session_id,
    )

    print(
        {
            "prompt_status": prompt_result.get("query_status"),
            "response_status": response_result.get("query_status"),
            "session_id": session_id,
        }
    )


if __name__ == "__main__":
    main()
