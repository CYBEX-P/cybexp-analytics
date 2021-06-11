"""CYBEX-P Analytics Module main script."""

import logging
import pdb
from queue import Queue
import random
import time

from filters import set_filter_backend, Cowrie, Email, OpenPhishFeed, \
    PhishTankFeed, Sighting


# Logging
# -------

logging.basicConfig(filename = 'analytics.log') 
logging.basicConfig(level=logging.ERROR,
    format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s' \
    ' - %(funcName)() --  %(message)s')


# Initialize Backends
# -------------------

def set_analytics_backend(backend):
    set_filter_backend(backend)


# Code
# ----

def exponential_backoff(n):
    s = min(3600, (2 ** n) + (random.randint(0, 1000) / 1000)) 
    time.sleep(s)


def infinite_worker(q):
    n_failed_attempts = 0
    
    while not q.empty():

        func = q.get()

        try:
            r = func()
            if not r:
                exponential_backoff(n_failed_attempts)
                n_failed_attempts += 1
            else:
                n_failed_attempts = 0

        except (KeyboardInterrupt, SystemExit):
            raise

        except:
            logging.error("Error in analytics.infinite_worker!", exc_info=True)
            exponential_backoff(n_failed_attempts)
            n_failed_attempts += 1
            
        q.task_done()
        q.put(func)


def analytics():
    try:
        filters = [Cowrie, Email, OpenPhishFeed, PhishTankFeed, Sighting]

        q = Queue()
        for f in filters:
            q.put(f().run)
        
        infinite_worker(q)

    except (KeyboardInterrupt, SystemExit):
        raise

    except Exception:
        logging.error("proc.analytics.analytics: ", exc_info=True)



if __name__ == "__main__":

    import loadconfig
    analytics_backend = loadconfig.get_tahoe_backend()
    set_analytics_backend(analytics_backend)

    analytics()

    

