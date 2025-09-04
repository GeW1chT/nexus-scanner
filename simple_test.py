import sys
import os

print("Nexus-Scanner Test")
print("================")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")

try:
    import nmap
    print("nmap module imported successfully")
except ImportError as e:
    print(f"Error importing nmap: {e}")

try:
    import requests
    print("requests module imported successfully")
except ImportError as e:
    print(f"Error importing requests: {e}")

print("\nTest completed!")