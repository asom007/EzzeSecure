"""cPanel/Passenger startup: configure the public origin and private state in env."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
from heimdall.wsgi import Application

application = Application(root)
