import os
import time
import socket

# Fake persistence attempt
os.system("echo 'test' >> fake_autostart.conf")

# Rapid file access (behavioral indicator)
for i in range(10):
    open(f"temp_{i}.txt", "w").write("test")
    time.sleep(0.2)

# Suspicious network pattern (localhost only)
s = socket.socket()
s.connect(("127.0.0.1", 80))
s.close()

print("Benign suspicious behavior simulation completed")
