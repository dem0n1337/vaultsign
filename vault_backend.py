"""Vault backend module for VaultSign.

Wraps all Vault/SSH operations as functions that run subprocesses.
Each function takes a config dict and returns (success: bool, output: str).
"""

import os
import subprocess
from typing import Callable, Optional, Tuple

StepCallback = Callable[[str, bool, str], None]


def _expand_key_path(config: dict) -> str:
    """Expand the SSH key path from config."""
    return os.path.expanduser(config["ssh_key_path"])


def _vault_env(config: dict) -> dict:
    """Build a subprocess environment with VAULT_ADDR set."""
    env = os.environ.copy()
    env["VAULT_ADDR"] = config["vault_addr"]
    return env


def check_prerequisites(config: dict, callback: Optional[StepCallback] = None) -> Tuple[bool, str]:
    """Verify vault CLI exists and SSH keys are present.

    Checks:
    - vault CLI exists at config["vault_cli_path"]
    - Private SSH key exists at config["ssh_key_path"]
    - Public SSH key exists at config["ssh_key_path"] + ".pub"

    Returns:
        (success, output) tuple.
    """
    messages = []
    vault_cli = config["vault_cli_path"]
    ssh_key = _expand_key_path(config)
    ssh_pub = ssh_key + ".pub"

    ok = True

    if os.path.isfile(vault_cli):
        messages.append(f"Vault CLI found: {vault_cli}")
    else:
        messages.append(f"Vault CLI NOT found: {vault_cli}")
        ok = False

    if os.path.isfile(ssh_key):
        messages.append(f"SSH private key found: {ssh_key}")
    else:
        messages.append(f"SSH private key NOT found: {ssh_key}")
        ok = False

    if os.path.isfile(ssh_pub):
        messages.append(f"SSH public key found: {ssh_pub}")
    else:
        messages.append(f"SSH public key NOT found: {ssh_pub}")
        ok = False

    output = "\n".join(messages)
    if callback is not None:
        callback("check_prerequisites", ok, output)
    return (ok, output)


def vault_login(config: dict, callback: Optional[StepCallback] = None) -> Tuple[bool, str]:
    """Run vault login with OIDC method.

    Executes: vault login -method=oidc role=ROLE

    The OIDC flow opens a browser for authentication. The subprocess
    blocks until the redirect completes.

    Returns:
        (success, output) tuple.
    """
    vault_cli = config["vault_cli_path"]
    role = config["role"]
    env = _vault_env(config)

    try:
        result = subprocess.run(
            [vault_cli, "login", "-method=oidc", f"role={role}"],
            capture_output=True,
            text=True,
            env=env,
        )
        output = result.stdout + result.stderr
        success = result.returncode == 0
        output = output.strip()
        if callback is not None:
            callback("vault_login", success, output)
        return (success, output)
    except FileNotFoundError:
        output = f"Vault CLI not found at: {vault_cli}"
        if callback is not None:
            callback("vault_login", False, output)
        return (False, output)
    except Exception as e:
        output = f"Error running vault login: {e}"
        if callback is not None:
            callback("vault_login", False, output)
        return (False, output)


def sign_ssh_key(config: dict, callback: Optional[StepCallback] = None) -> Tuple[bool, str]:
    """Sign the SSH public key via Vault.

    Executes: vault write -field=signed_key ssh-client-signer/sign/ROLE
              public_key=@PUBKEY

    Writes the signed certificate to SSH_KEY_PATH-cert.pub.

    Returns:
        (success, output) tuple.
    """
    vault_cli = config["vault_cli_path"]
    role = config["role"]
    ssh_key = _expand_key_path(config)
    ssh_pub = ssh_key + ".pub"
    cert_path = ssh_key + "-cert.pub"
    env = _vault_env(config)

    try:
        result = subprocess.run(
            [
                vault_cli,
                "write",
                "-field=signed_key",
                f"ssh-client-signer/sign/{role}",
                f"public_key=@{ssh_pub}",
            ],
            capture_output=True,
            text=True,
            env=env,
        )

        if result.returncode != 0:
            output = (result.stdout + result.stderr).strip()
            if callback is not None:
                callback("sign_ssh_key", False, output)
            return (False, output)

        signed_key = result.stdout.strip()
        if not signed_key:
            output = "Vault returned empty signed key."
            if callback is not None:
                callback("sign_ssh_key", False, output)
            return (False, output)

        with open(cert_path, "w") as f:
            f.write(signed_key + "\n")

        output = f"Certificate written to {cert_path}"
        if callback is not None:
            callback("sign_ssh_key", True, output)
        return (True, output)
    except FileNotFoundError:
        output = f"Vault CLI not found at: {vault_cli}"
        if callback is not None:
            callback("sign_ssh_key", False, output)
        return (False, output)
    except Exception as e:
        output = f"Error signing SSH key: {e}"
        if callback is not None:
            callback("sign_ssh_key", False, output)
        return (False, output)


def add_to_ssh_agent(config: dict, callback: Optional[StepCallback] = None) -> Tuple[bool, str]:
    """Ensure ssh-agent is running and add the private key.

    Tries systemctl --user start ssh-agent first, falls back to
    eval ssh-agent -s. Then runs ssh-add PRIVATE_KEY.

    Note: When the fallback ssh-agent path is taken, this function mutates
    os.environ by setting SSH_AUTH_SOCK and SSH_AGENT_PID so that the
    subsequent ssh-add subprocess (and any later subprocesses in this
    process) can connect to the agent.

    Returns:
        (success, output) tuple.
    """
    ssh_key = _expand_key_path(config)
    messages = []

    # Try to start ssh-agent via systemctl first
    agent_started = False
    try:
        result = subprocess.run(
            ["systemctl", "--user", "start", "ssh-agent"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            messages.append("ssh-agent started via systemctl.")
            agent_started = True
        else:
            messages.append("systemctl ssh-agent start failed, trying fallback.")
    except FileNotFoundError:
        messages.append("systemctl not found, trying fallback.")

    # Fallback: start ssh-agent manually and capture its environment
    if not agent_started:
        try:
            result = subprocess.run(
                ["ssh-agent", "-s"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse SSH_AUTH_SOCK and SSH_AGENT_PID from output
                for line in result.stdout.splitlines():
                    if line.startswith("SSH_AUTH_SOCK="):
                        sock = line.split(";")[0].split("=", 1)[1]
                        os.environ["SSH_AUTH_SOCK"] = sock
                    elif line.startswith("SSH_AGENT_PID="):
                        pid = line.split(";")[0].split("=", 1)[1]
                        os.environ["SSH_AGENT_PID"] = pid
                messages.append("ssh-agent started via ssh-agent -s.")
                agent_started = True
            else:
                messages.append(f"ssh-agent -s failed: {result.stderr.strip()}")
        except FileNotFoundError:
            messages.append("ssh-agent command not found.")
        except Exception as e:
            messages.append(f"Error starting ssh-agent: {e}")

    if not agent_started:
        output = "\n".join(messages)
        if callback is not None:
            callback("add_to_ssh_agent", False, output)
        return (False, output)

    # Run ssh-add
    try:
        result = subprocess.run(
            ["ssh-add", ssh_key],
            capture_output=True,
            text=True,
        )
        cmd_output = result.stdout + result.stderr
        messages.append(cmd_output.strip())
        output = "\n".join(messages)
        success = result.returncode == 0
        if callback is not None:
            callback("add_to_ssh_agent", success, output)
        return (success, output)
    except FileNotFoundError:
        messages.append("ssh-add command not found.")
        output = "\n".join(messages)
        if callback is not None:
            callback("add_to_ssh_agent", False, output)
        return (False, output)
    except Exception as e:
        messages.append(f"Error running ssh-add: {e}")
        output = "\n".join(messages)
        if callback is not None:
            callback("add_to_ssh_agent", False, output)
        return (False, output)


def get_certificate_details(config: dict, callback: Optional[StepCallback] = None) -> Tuple[bool, str]:
    """Show details of the signed SSH certificate.

    Executes: ssh-keygen -L -f CERT_PATH

    Returns:
        (success, output) tuple.
    """
    ssh_key = _expand_key_path(config)
    cert_path = ssh_key + "-cert.pub"

    try:
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", cert_path],
            capture_output=True,
            text=True,
        )
        output = (result.stdout + result.stderr).strip()
        success = result.returncode == 0
        if callback is not None:
            callback("get_certificate_details", success, output)
        return (success, output)
    except FileNotFoundError:
        output = "ssh-keygen command not found."
        if callback is not None:
            callback("get_certificate_details", False, output)
        return (False, output)
    except Exception as e:
        output = f"Error reading certificate: {e}"
        if callback is not None:
            callback("get_certificate_details", False, output)
        return (False, output)


def run_full_auth(
    config: dict,
    step_callback: Optional[StepCallback] = None,
) -> Tuple[bool, str]:
    """Orchestrate the full authentication flow.

    Runs steps sequentially:
    1. check_prerequisites
    2. vault_login
    3. sign_ssh_key
    4. add_to_ssh_agent
    5. get_certificate_details

    Calls step_callback(step_name, success, output) after each step.
    Stops on first failure.

    Returns:
        (success, output) tuple from the last executed step.
    """
    steps = [
        ("check_prerequisites", check_prerequisites),
        ("vault_login", vault_login),
        ("sign_ssh_key", sign_ssh_key),
        ("add_to_ssh_agent", add_to_ssh_agent),
        ("get_certificate_details", get_certificate_details),
    ]

    for step_name, step_func in steps:
        success, output = step_func(config, callback=step_callback)

        if not success:
            return (False, f"Failed at {step_name}: {output}")

    return (True, output)
