import os, subprocess, time
from subprocess import *            #subprocess의 Popen 함수 옵션인 PIPE가 오류가 나서 추가하였음.
from multiprocessing import Pool
import pandas as pd

def feature_name():
    readFile = open('.\\yara_config\\packer_parser_name.txt', 'r')
    featureNameList = [i.replace('\n','') for i in readFile]
    readFile.close()
    return featureNameList


def test_getYaraResult(yaraCheckFilePath, fileName):
    yaraProgramPath = '.\\yara_config\\yara64.exe'                    # yara 실행파일 위치
    yaraRulePath = '.\\yara_config\\rules\\includeRules.yar'           # yara 룰셋 저장 경로
    
    yaraResult = {}
    yaraResultCall = subprocess.Popen([yaraProgramPath, yaraRulePath, yaraCheckFilePath], stdout=PIPE).communicate()[0]
    yaraResultCall = yaraResultCall.decode('utf-8').split(f' {yaraCheckFilePath}\r\n')
    del yaraResultCall[-1]
    # print(yaraResultCall)

    featureNameList = feature_name()

    featureVector = []
    index = 0
    lastIndex = len(yaraResultCall)
    for i in featureNameList:
        if i == yaraResultCall[index]:
            try:
                featureVector.append(1)
                if lastIndex-1 > index:
                    index += 1
            except:
                print(fileName + "  에러에러!!!!!!!!!")
        else:
            featureVector.append(0)

    yaraResult[fileName] = featureVector

    pd_data = pd.DataFrame.from_dict(yaraResult, orient='index', columns=feature_name())
    
    return pd_data

# if __name__  == '__main__':
#     startTime = time.time()

#     yaraProgramPath = './yara64.exe'
#     yaraRulePath = './rules/includeRules.yar'
#     yaraCheckFilePath = './dataset/malware/'
#     yaraCheckFileList = os.listdir(yaraCheckFilePath)
    
#     # a = [test_getYaraResult(yaraProgramPath, yaraRulePath, yaraCheckFilePath, '5561df20b0732b7d0c5a5d30db9d359da0c962033d668d1cd90b47734f17b151.vir')]
    
#     result = {}
#     with Pool(processes=10) as p:
#         res = [p.apply_async(test_getYaraResult, args=(yaraProgramPath, yaraRulePath, yaraCheckFilePath, fileName)) for fileName in yaraCheckFileList]
#         for r in res:
#             result.update(r.get())

#     pd_data = pd.DataFrame.from_dict(result, orient='index', columns=feature_name())
#     pd_data.to_csv('test.csv', mode='w', encoding='utf-8-sig')

#     print(f'Time : {time.time() - startTime}')