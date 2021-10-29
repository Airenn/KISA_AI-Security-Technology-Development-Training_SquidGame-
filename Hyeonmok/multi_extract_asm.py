import os
import timeit
from multiprocessing import Process, Queue

# ------------Custom Py--------------#
import config as conf
import extract_asm as ext
import make_futerue as futerue


TIMEOUT = 300

def GET_IDB_LIST(DIR_PATH, q):
    q = Queue()
    for file in os.listdir(DIR_PATH):
        if file[-4:] == '.idb':
            q.put(DIR_PATH + file)
    return q

def GET_JSON_LIST(DIR_PATH, _q):
    _q = Queue()
    for file in os.listdir(DIR_PATH):
        if file[-5:] == '.json':
            _q.put(DIR_PATH + file)
    return _q

def extraction_IDB_MULTI(q):
    while q.qsize():
        ext.extraction_IDB(q.get())

def anlys_JSON_MULTI(q):
    while q.qsize():
        futerue.MAKE_FUTERUE(q.get())

if __name__ == "__main__":

    t = timeit.default_timer()
    idb_list_q = Queue()
    idb_list_q = GET_IDB_LIST(conf.IDB_PATH, idb_list_q)

    procs = list()
    for i in range(os.cpu_count()-1):
        proc = Process(target=extraction_IDB_MULTI, args=[idb_list_q, ])
        procs.append(proc)
        proc.start()

    for p in procs:
        p.join(timeout=TIMEOUT)

    del t, idb_list_q, procs
    print(f'[+][END extract_asm.py Running Time] : {timeit.default_timer() - t}')

    t = timeit.default_timer()
    json_list_q = Queue()
    json_list_q = GET_JSON_LIST(conf.EXT_IDB_JSON_PATH, json_list_q)

    procs = list()
    for i in range(os.cpu_count()-1):
        proc = Process(target=anlys_JSON_MULTI, args=[json_list_q, ])
        procs.append(proc)
        proc.start()

    for p in procs:
        p.join()

    del t, idb_list_q, procs
    print(f'[+][END make_futerue.py Running Time] : {timeit.default_timer() - t}')