"""Render the real chart to guard the provider credential/network boundary."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[3] / "contrib/chart"


@pytest.mark.skipif(not shutil.which("helm"), reason="Helm is required for chart contracts")
@pytest.mark.parametrize("general_policy", ["true", "false"])
def test_provider_policy_and_credentials(general_policy):
    rendered = subprocess.check_output(
        [
            "helm",
            "template",
            "test",
            str(CHART),
            "--set",
            "telegram.enabled=true",
            "--set",
            "telegram.image.tag=synthetic-test",
            "--set",
            "telegram.existingSecretName=synthetic-telegram",
            "--set",
            f"networkPolicy.enabled={general_policy}",
        ],
        text=True,
    )
    docs = [x for x in yaml.safe_load_all(rendered) if x]
    worker = next(
        x for x in docs if x["kind"] == "Deployment" and x["metadata"]["name"].endswith("-telegram")
    )
    assert worker["spec"]["replicas"] == 1
    assert worker["spec"]["strategy"]["type"] == "Recreate"
    pod = worker["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    policy = next(
        x
        for x in docs
        if x["kind"] == "NetworkPolicy" and x["metadata"]["name"].endswith("-telegram")
    )
    ingress = policy["spec"]["ingress"]
    assert len(ingress) == 1
    assert len(ingress[0]["from"]) == 1
    assert (
        ingress[0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        == "console"
    )
    for resource in docs:
        spec = resource.get("spec", {}).get("template", {}).get("spec", {})
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            refs = {
                e.get("valueFrom", {}).get("secretKeyRef", {}).get("key")
                for e in container.get("env", [])
            }
            private = refs & {"TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_SESSION_KEY"}
            assert not private or (resource is worker and container["name"] == "telegram")
    console_policies = [
        x
        for x in docs
        if x["kind"] == "NetworkPolicy" and x["metadata"]["name"].endswith("-console")
    ]
    if general_policy == "false":
        # Telegram must not accidentally isolate an otherwise unrestricted Console.
        assert not console_policies
    else:
        ports = {
            p["port"]
            for rule in console_policies[0]["spec"]["egress"]
            for p in rule.get("ports", [])
        }
        assert {443, 5432, 8000} <= ports
