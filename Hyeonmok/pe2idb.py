import os
import pefile
import subprocess
import timeit
from multiprocessing import Process, Queue

# ------------Custom Py--------------#
import config as conf

IDAT_PATH = [
    conf.idat_PATH,
    conf.idat64_PATH
]

BYTES_SIG_MZ = b'MZ'  # '0x5A4D' / DOS Header (0~64bytes) Magic number
BYTES_SIG_PE = b'PE'  # '0x4550' / NT Header

HEX_M_32 = 0x14c
HEX_M_64_IA = 0x200
HEX_M_64_AMD = 0x8664

IDAT = 0
IDAT64 = 1
PE_UNKNOWN = -1
PE_CHECK_ERROR = -2


def CHECK__PE(File):
    f = open(File, 'rb')
    rbdata = f.read()
    f.close()

    # [DEBUG] print(binascii.hexlify(rbdata[64:512]))
    if (rbdata[0:2] == BYTES_SIG_MZ) or (rbdata[2:512].find(BYTES_SIG_PE) != -1):

        del rbdata
        try:
            pe = pefile.PE(File, fast_load=True)
            mBit = pe.FILE_HEADER.Machine
            pe.close()
            del pe
            if mBit == HEX_M_32:
                return IDAT
            elif mBit == HEX_M_64_AMD or mBit == HEX_M_64_IA:
                return IDAT64
            else:
                # Q. 머신비트가 0x1C2(450), 0x1C4(452) 나오는 애들은 뭐지... why..?
                # print(f"[Debug] {File} is {mBit =}")
                return PE_UNKNOWN
        except:
            # PE지만 패킹 등 으로 인해 PEFILE 모듈을 사용할 수 없는 경우 분기
            # 비트 수 파악이 어려워 idat.exe로 돌려보고 exception 발생 시 idat64.exe로 처리
            return PE_UNKNOWN

    else:
        # PE 가 아닌 경우 분기
        return PE_CHECK_ERROR


def GET__FILE_LIST(Path):
    FILES_PATH = list()
    for i in os.listdir(Path):
        FILES_PATH.append(Path + i)
    return FILES_PATH


def LIST_TO_QUEUE(FILES_PATH, q):
    for f in GET__FILE_LIST(FILES_PATH):
        q.put(f)
    return q


def EXECUTE_IDAT(FILE_PATH, pe_flag):
    # idat command
    # -A :
    # -B : batch mode. IDA는 .IDB와 .ASM 파일을 자동 생성
    # -P : 압축된 idb를 생성한다.
    # WSL_PATH_CORRECT 으로 경로를 강제 FIX
    # FILE_PATH = WSL_PATH_CORRECT(FILE_PATH)
    if pe_flag == IDAT or pe_flag == IDAT64:
        try:
            # print(f'{IDAT_PATH=}  {pe_flag=} {FILE_PATH= }')
            process = subprocess.Popen([IDAT_PATH[pe_flag], "-A", "-B", "-P+", FILE_PATH], shell=False)
            process.wait()
        except:
            print('[DEBUG] CONVERT IDAT ERROR({pe_flag}) : {FILE_PATH}')
        return pe_flag

    else:
        # pe_flag가 IDAT(0) 혹은 IDAT(1)이 아닌 경우에는 먼저 idat.exe을 실행
        # idat.exe 실행간 exception 발생 시 idat64.exe를 실행
        try:
            process = subprocess.Popen([IDAT_PATH[IDAT], "-A", "-B", "-P+", FILE_PATH], shell=False)
            process.wait()
            return IDAT

        except:
            process = subprocess.Popen([IDAT_PATH[IDAT64], "-A", "-B", "-P+", FILE_PATH], shell=False)
            process.wait()
            return IDAT64


def EXE_TO_IDB(q, ):
    while q.empty() != True:
        # while q.qsize():
        FILE_PATH = q.get()
        try:
            pe_flag = CHECK__PE(FILE_PATH)
            # print(f'{FILE_PATH}')
            if pe_flag != PE_CHECK_ERROR:
                p = EXECUTE_IDAT(FILE_PATH, pe_flag)

            else:
                # NONE TYPE 에러처리구간
                pass

        except Exception as e:
            print(f'[Debug] ERROR PE FORMAT')
            print(f'  ㄴ {e}')


def CLEAR_DIR(DIR_PATH):
    file_list = os.listdir(DIR_PATH)
    try:
        for f in file_list:
            if '.asm' in f:
                os.remove(os.path.join(DIR_PATH, f))
        return True
    except:
        return False


def CREATE_IDB(PATH, ):
    # 시간측정
    t = timeit.default_timer()

    # 파일 리스트를 큐에 삽입
    q = Queue()
    q = LIST_TO_QUEUE(PATH, q)

    procs = list()
    for i in range(os.cpu_count()):
        proc = Process(target=EXE_TO_IDB, args=[q, ])
        procs.append(proc)
        proc.start()

    for p in procs:
        p.join()  # 프로세스 종료까지 wait

    print(f'[+][Running Time] : {timeit.default_timer() - t}')
    return CLEAR_DIR(PATH)


def WSL_PATH_CORRECT(PATH):
    # WSL2 기준으로 idat한테 일시킬 때 /mnt/d/...로가면 못찾는다. 경로 강제 보정 함수
    # WSL 버려 ㅡㅡ 안해
    return (PATH.split('/mnt/')[1][:1].upper() + ':' + PATH.split('/mnt/')[1][1:]).replace('/', '\\')


if __name__ == '__main__':
    CREATE_IDB(conf.PE_PATH)

