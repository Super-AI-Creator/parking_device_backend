"""Background PMS booking sync every 1 minute."""

from datetime import datetime
import logging
import os
import atexit
import threading

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_scheduler = BackgroundScheduler()
_lock = threading.Lock()
_running = False


def _job() -> None:
    global _running
    if not _lock.acquire(blocking=False):
        return
    if _running:
        _lock.release()
        return
    _running = True
    _lock.release()
    try:
        from booking_sync import sync_all_managers

        sync_all_managers()
    except Exception:
        logger.exception("Scheduled PMS sync failed")
    finally:
        _running = False


def start_scheduler() -> None:
    if os.getenv("RUN_SCHEDULER", "true").lower() in {"0", "false", "no"}:
        logger.info("PMS scheduler disabled")
        return
    if _scheduler.running:
        return
    _scheduler.add_job(
        _job,
        trigger=IntervalTrigger(minutes=1),
        id="pms_booking_sync",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(),
    )
    _scheduler.start()
    atexit.register(lambda: _scheduler.shutdown(wait=False) if _scheduler.running else None)
    logger.info("PMS booking sync scheduled every 1 minute")
