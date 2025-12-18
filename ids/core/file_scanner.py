from pathlib import Path

MALICIOUS_SIGNATURES = [
    "os.system(",
    "subprocess.Popen(",
    "eval(",
    "exec(",
    "base64.b64decode(",
    "socket.socket(",
    "requests.post(",
    "pickle.loads("
]

class FileScanner:
    def scan_file(self, file_path: str):
        file_path = Path(file_path)

        if not file_path.exists():
            return {"status": "error", "message": "File not found"}

        try:
            content = file_path.read_text(errors="ignore")
        except Exception as e:
            return {"status": "error", "message": str(e)}

        hits = []
        for sig in MALICIOUS_SIGNATURES:
            if sig in content:
                hits.append(sig)

        if hits:
            return {
                "status": "malicious",
                "file": str(file_path),
                "signatures_detected": hits
            }

        return {
            "status": "clean",
            "file": str(file_path)
        }
