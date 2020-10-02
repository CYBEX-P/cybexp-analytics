# proc\analytics\analytics.py

from queue import Queue
import time, logging, copy, random, os, pdb
from filters import filt_cowrie  

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

        except Exception as exception:
            logging.error("proc.analytics.infinite_worker: ", exc_info=True)
            exponential_backoff(n_failed_attempts)
            n_failed_attempts += 1
            
        q.task_done()
        q.put(func)

def analytics():
    try:       
        q = Queue()
        q.put(filt_cowrie)
        
        infinite_worker(q)

    except (KeyboardInterrupt, SystemExit):
        raise

    except Exception:
        logging.error("proc.analytics.analytics: ", exc_info=True)

if __name__ == "__main__":

##    logging.basicConfig(filename = '../proc.log')
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s:%(message)s')
 
    analytics()

    

