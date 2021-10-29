import json
import csv

import config as conf

def open_JSON(path):
    with open(path) as json_file:
        json_data = json.load(json_file)
    return json_data

def cnt_opgram(path):
    data = open_JSON(path)

    file_name = list(data.keys())[0]
    OpCntDic = dict()
    for func in data[file_name]:
        if func != "opcodes_all":
            for op_GRAM in list(data[file_name][func].values())[0]["OP-GRAM"]:
                try:
                    OpCntDic[op_GRAM] = OpCntDic[op_GRAM] + 1
                except:
                    OpCntDic[op_GRAM] = 1
    return sorted(OpCntDic.items(), key=(lambda x: x[1]), reverse=True), file_name


def save_csv(data):
    with open(conf.CSV_PATH + 'result.csv', 'a', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(data)

def MAKE_FUTERUE(json_path):
    sort_data, file_name = cnt_opgram(json_path)

    #상위 5개의 opcodes GRAM만 불러오기
    top_data = tuple()
    for i in range(0, 5):
        top_data = top_data + sort_data[i]

    top_opcodes = list(top_data)
    top_opcodes.insert(0, file_name)

    top_opcodes[1] = top_opcodes[1].replace(' ', '_')
    top_opcodes[3] = top_opcodes[3].replace(' ', '_')
    top_opcodes[5] = top_opcodes[5].replace(' ', '_')

    save_csv(top_opcodes)

    return file_name


if __name__ == "__main__":

    test_path = r'D:\\test2\\8feaeac33e79a552e1b7254bae79306d98fed0f9a5e7ecb5119389d959c09d9a.json'
    file_name = MAKE_FUTERUE(test_path)
    print(f'[INFO] {file_name} futerue extract Success')