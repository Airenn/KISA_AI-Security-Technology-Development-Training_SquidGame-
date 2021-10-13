# File_Classification.py
# OLE(Doc, Hwp)
# PE
# UPX(+Unpaking)

import olefile

import os
import struct
import shutil

target_path = input("분류할 파일들이 존재하는 경로를 입력하세요(절대경로) : ")       # 분류 대상 파일 존재하는 경로

# 분류할 파일 리스트
classification_folder_list = ['PE', 'DOC', 'HWP', 'UPX']

# 분류시킬 폴더 생성
for folder in classification_folder_list:
    if os.path.isdir((target_path + '\\' + folder)) == False:
        os.mkdir(target_path + '\\' + folder)

dirs = os.listdir(target_path)

for dir in classification_folder_list:  # 분류할 파일만 리스트에 저장하기 위해 폴더 목록 제거
    dirs.remove(dir)

def get_dword(buf, off):
    return struct.unpack('<L', buf[off:off+4])[0]

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
    buf = fp.read(10240)
    fp.close()

    # PE 파일 찾기
    if buf[:2] == b'MZ':
        off = get_dword(buf, 0x3c)
        off_upx = off + 0xF8
        if buf[off_upx:off_upx+4] == b'UPX0':
            print('UPX로 이동 : ', name)
            shutil.move(fname, target_path + '\\UPX')
        elif buf[off:off+2] == b'PE':
            print('PE로 이동 : ', name)
            shutil.move(fname, target_path + '\\PE')

# UPX 파일 Unpack
if os.path.isdir(target_path + '\\UPX') == True:
    os.chdir(os.path.dirname(os.path.realpath(__file__)) + '\\upx396')  # cmd 명령어로 실행하기 위해 경로 이동

    if os.path.isdir((target_path + '\\UPX\\' + 'UnPacked')) == False:
        os.mkdir(target_path + '\\UPX\\' + 'UnPacked')

    dir_upx = os.listdir(target_path + '\\UPX')
    dir_upx.remove('UnPacked')

    # Unpacking이 된 파일 찾기
    for file_upx in dir_upx:
        os.system('upx -d ' + target_path + '\\UPX\\' + file_upx)

        fname = target_path + '\\UPX\\' + file_upx
        fp = open(fname, 'rb')
        buf = fp.read(10240)
        fp.close()

        if buf[:2] == b'MZ':
            off_upx = get_dword(buf, 0x3c)
            off_upx += 0xF8
        if buf[off_upx:off_upx+4] != b'UPX0':   # 섹션명이 UPX0가 아니면 Unpacking이 된 것
            print('UnPacked로 이동 : ', file_upx)
            shutil.move(fname, target_path + '\\UPX\\' + 'UnPacked')