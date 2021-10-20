# File_Classification.py
# OLE(Doc, Hwp)
# PE
# Unpaking

import olefile
import yara

import os
import struct
import shutil

def get_dword(buf, off):
    return struct.unpack('<L', buf[off:off+4])[0]

target_path = input("분류할 파일들이 존재하는 경로를 입력하세요(절대경로) : ")       # 분류 대상 파일 존재하는 경로

# 분류할 파일 리스트
classification_folder_list = ['PE', 'DOC', 'HWP']
classification_folder_packing_list = ['UPX', 'PETITE', 'MPRESS_2', 'MEW', 'FSG', 'ASPACK']  # PE 폴더 내에 만들 리스트(대문자로 작성)

# 분류시킬 폴더 생성
for folder in classification_folder_list:
    if os.path.isdir((target_path + '\\' + folder)) == False:
        os.mkdir(target_path + '\\' + folder)

for packing_folder in classification_folder_packing_list:
    if os.path.isdir((target_path + '\\PE\\' + packing_folder)) == False:
        os.mkdir(target_path + '\\PE\\' + packing_folder)

dirs = os.listdir(target_path)

for dir in classification_folder_list:  # 분류할 파일만 리스트에 저장하기 위해 폴더 목록 제거
    dirs.remove(dir)

# Packing Rule 불러오기
packing_rule = yara.compile(filepath=os.path.dirname(os.path.realpath(__file__)) + '\\rules-master\\packers\\packer.yar')

for name in dirs:
    fname = os.path.join(target_path, name)
    
    ##### OLE 파일 분류 #####
    if olefile.isOleFile(fname) == True:
        ### DOC 분류 ###
        ole = olefile.OleFileIO(fname)
        if ole.exists('WordDocument'):
            ole.close()
            print('DOC로 이동 : ', name)
            shutil.move(fname, target_path + '\\DOC')  # 분류 대상 경로 내 DOC 폴더로 이동
        ### HWP 분류 ###
        elif ole.exists('FileHeader'):
            fh = ole.openstream('FileHeader')
            data = fh.read()
            if data[0:3] == b'HWP':
                ole.close()
                print('HWP로 이동 : ', name)
                shutil.move(fname, target_path + '\\HWP')  # 분류 대상 경로 내 HWP 폴더로 이동
        else:
            print('HWP_No_FileHeader로 이동 : ', name)
            shutil.move(fname, target_path + '\\HWP_No_FileHeader')  # 분류 대상 경로 내 FileHeader가 없는 HWP 파일을 폴더로 이동
        continue
    fp = open(fname, 'rb')
    buf = fp.read(1024)
    fp.close()

    ### PE 파일 분류 ###
    if buf[:2] == b'MZ':
        off = get_dword(buf, 0x3c)
        if buf[off:off+2] == b'PE':
            print('PE로 이동 : ', name)
            shutil.move(fname, target_path + '\\PE')
            packing_list = list(map(str, packing_rule.match(target_path + '\\PE\\' + name)))    # 해당 파일과 Packing Rule과 일치하는 Packing 리스트를 문자열로 변환
            packing_list = [u.upper() for u in packing_list]                                    # 대문자 변환

            # PE 파일이 Packing이 되어있으면 해당 폴더로 이동
            for packing in classification_folder_packing_list:
                if [p for p in packing_list if packing in p]:
                    print('PE\\'+ packing + '로 이동 : ' + name)
                    shutil.move(target_path + '\\PE\\' + name, target_path + '\\PE' + '\\' + packing)
### UnPacking ###
# UPX
if os.path.exists(target_path + '\\PE\\UPX') == True:
    os.chdir(os.path.dirname(os.path.realpath(__file__)) + '\\upx396')  # cmd 명령어로 실행하기 위해 경로 이동

    if os.path.isdir((target_path + '\\PE\\UPX\\' + 'UnPacked')) == False:
        os.mkdir(target_path + '\\PE\\UPX\\' + 'UnPacked')

        dir_upx = os.listdir(target_path + '\\PE\\UPX')
        dir_upx.remove('UnPacked')

    # Unpacking이 된 파일 찾기
    for file_upx in dir_upx:
        os.system('upx -d ' + target_path + '\\PE\\UPX\\' + file_upx)

        fname = target_path + '\\PE\\UPX\\' + file_upx
        fp = open(fname, 'rb')
        buf = fp.read(10240)
        fp.close()

        if buf[:2] == b'MZ':
            off_upx = get_dword(buf, 0x3c)
            off_upx += 0xF8
        if buf[off_upx:off_upx+4] != b'UPX0':   # 섹션명이 UPX0가 아니면 Unpacking이 된 것
            shutil.move(fname, target_path + '\\PE\\UPX\\' + 'UnPacked')

# UPX를 제외한 나머지
classification_folder_packing_list.remove('UPX')
for packing_dir in classification_folder_packing_list:
    os.system('unipacker ' + target_path +'\\PE\\'+ packing_dir + ' -d ' + target_path +'\\PE\\' + packing_dir + '\\UnPacked')
