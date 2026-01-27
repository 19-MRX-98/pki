import subprocess


def run_openssl(args: list[str]) -> None:
    subprocess.run(["openssl", *args], check=True)


def run_openssl_capture(args: list[str]) -> str:
    result = subprocess.run(
        ["openssl", *args], check=True, capture_output=True, text=True
    )
    return result.stdout
