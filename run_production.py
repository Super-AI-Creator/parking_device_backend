"""Production entrypoint: waitress serving Flask + built frontend."""

from waitress import serve

import config
from app import app

if __name__ == "__main__":
    print(f"{config.APP_NAME} listening on http://{config.HOST}:{config.PORT}")
    serve(app, host=config.HOST, port=config.PORT, threads=8)
