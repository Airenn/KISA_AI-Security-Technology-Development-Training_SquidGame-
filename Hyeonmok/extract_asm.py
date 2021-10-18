# pip3 install capstone
# pip3 install python-idb
import idb
import json
import timeit
from multiprocessing import Queue
from concurrent import futures

# ------------Custom Py--------------#
import config as conf

THREAD_WORKERS = 1000
PRODCESS_WORKERS = 20

def OPEN_IDB(FROM_FILE):

    global filename
    filename = FROM_FILE[FROM_FILE.rfind('\\') + 1:-4]

    with idb.from_file(FROM_FILE) as db:
        api = idb.IDAPython(db)
        return api

def SEARCH_FUNC():
    global filename
    global api
    global imageBase
    global glo_MaxEA
    global glo_MinEA
    global err_log
    global except_list

    glo_MaxEA = int(hex(api.idc.MaxEA()), 16)
    glo_MinEA = int(hex(api.idc.MinEA()), 16)
    # imageBase.append(str(hex(api.idaapi.get_imagebase())))
    q_jobs = Queue()
    complete_workers = list()
    bb_Info = dict()

    for fva in api.idautils.Functions():
        FuncName = api.idc.GetFunctionName(fva).lower()
        ''' 해당 PE에 존재하는 모든 함수 '''
            # print(FuncName)
        ''' ------------------------ '''

        # 함수필터
        if 'dllentry' in FuncName or FuncName[:3] == 'sub' or FuncName[:5] == 'start' or (FuncName.find('main') != -1 and FuncName.find('domain') == -1):
            # GET_BASICBLOCK_INFO(fva, FuncName, func_ext_dict)
            # func_name.append(FuncName)
            q_jobs.put(fva)

    bb_Info[filename] = dict()
    with futures.ThreadPoolExecutor(max_workers=THREAD_WORKERS) as executor:
        # for _fva in :
        while q_jobs.qsize():
            fs = executor.submit(GET_BASICBLOCK_INFO, q_jobs.get())
            complete_workers.append(fs)

        for future in futures.as_completed(complete_workers):
            res = future.result(timeout=50)
            # pprint.pprint(res)
            if not res:
                continue
            else:
                loc = list(res.keys())[0]
                bb_Info[filename][loc] = res[loc]

    return bb_Info


def GET_BASICBLOCK_INFO(fva):

    function_block = list()
    mutex_opcode_list = list()

    _function = api.ida_funcs.get_func(fva)
    flowchart = api.idaapi.FlowChart(_function)
    tempdict = dict()
    extract_result = dict()

    for baiscblock in flowchart:
        curaddr = baiscblock.startEA
        endaddr = baiscblock.endEA
        opcodes = list()
        #disasms = list()

        # #최소 바이트 50이상일 때 추출
        # #해당 조건 활성 시 평균 3~40% 이상 시간 단축 가능
        # if (baiscblock.endEA - baiscblock.startEA) < 35:
        #     continue

        try:
            while curaddr < endaddr:
                #opcode = api.idc.GetMnem(curaddr)
                disasm = api.idc.GetDisasm(curaddr)
                cutNumber = disasm.find('\t')
                opcode = disasm[:cutNumber]
                opcodes.append(opcode)
                #disasms.append(disasm)
                curaddr = api.idc.NextHead(curaddr)
        except Exception as e:
            print(f"[ERROR] {e}")
            continue

        # 중복 값 제어
        # mutex_opcode = ' '.join(opcodes)
        # if mutex_opcode in mutex_opcode_list:
        #     continue
        # else:
        #    mutex_opcode_list.append(mutex_opcode)

        # function_name = api.idc.GetFunctionName(fva).upper()
        basic_blocK_opcode_all = ' '.join(opcodes)
        tempdict[hex(curaddr)] = {"opcodes": basic_blocK_opcode_all}

        del opcodes
        extract_result[api.idc.GetFunctionName(fva).upper()] = tempdict
    # print(f'{tempdict.keys()} ==== {len(tempdict.keys())}') # basic block count

    return extract_result


def extraction_IDB(IDB):

    global api
    global filename
    api = OPEN_IDB(IDB)
    print(f'[INFO][Extract ASM] {filename}')

    return SAVE_JSON(SEARCH_FUNC())


def SAVE_JSON(data):
    with open(conf.EXT_IDB_JSON_PATH + filename+".json", 'w') as makefile:
        json.dump(data, makefile, ensure_ascii=False, indent='\t')


if __name__ == "__main__":

    s = timeit.default_timer()  # start time
    data = extraction_IDB(conf.IDB_PATH + "8feaeac33e79a552e1b7254bae79306d98fed0f9a5e7ecb5119389d959c09d9a.idb") # 가능 11 ([ERROR] failed to disassemble 0x407912)
    # SAVE_JSON(data)
    print(f"[INFO] Total running time : {timeit.default_timer() - s}")  # end time
