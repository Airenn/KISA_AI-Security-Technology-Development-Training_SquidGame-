import os
import timeit
from multiprocessing import Process, Queue

# ------------Custom Py--------------#
import config as conf
import extract_asm as ext

def GET_IDB_LIST(DIR_PATH, q):
    q = Queue()
    for file in os.listdir(DIR_PATH):
        if file[-4:] == '.idb':
            q.put(DIR_PATH + file)
    return q

def extraction_IDB_MULTI(q):
    while q.qsize():
        ext.extraction_IDB(q.get())



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
        p.join()

    print(f'[+][Running Time] : {timeit.default_timer() - t}')