"""Verify the individual worker distribution boundary using only offline runs."""

import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile


def call(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


image = sys.argv[1]
config = json.loads(call("docker", "image", "inspect", "--format", "{{json .Config}}", image))
assert config["User"] == "65532:65532"
assert config["Entrypoint"] == ["/openuem-worker"]
assert config["Cmd"] == ["agents", "start"]
assert "OPENUEM_INDIVIDUAL_AGENT_MODE=true" in config["Env"]
assert not config.get("ExposedPorts")
assert not config.get("Healthcheck")
assert config["StopSignal"] == "SIGTERM"

run = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
       "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", image]
assert "Manage an OpenUEM worker" in call(*run, "--help")
missing = subprocess.run(run, text=True, capture_output=True, timeout=15)
assert missing.returncode != 0
assert "individual agent worker requires a database URL" in missing.stderr

container = call("docker", "create", image, "--help")
try:
    with tempfile.TemporaryDirectory() as directory:
        archive = str(pathlib.Path(directory) / "runtime.tar")
        subprocess.run(["docker", "export", "-o", archive, container], check=True)
        with tarfile.open(archive) as stream:
            names = [entry.name.removeprefix("./").lstrip("/") for entry in stream if entry.isfile()]
        assert "openuem-worker" in names and "licenses/openuem-worker.LICENSE" in names
        assert [name for name in names if name.startswith("openuem-")] == ["openuem-worker"]
        allowed = {"openuem-worker", "licenses/openuem-worker.LICENSE",
                   "etc/hostname", "etc/hosts", "etc/resolv.conf", "dev/console", ".dockerenv"}
        assert set(names) <= allowed
finally:
    subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
print("individual worker image: private runtime boundary verified")
