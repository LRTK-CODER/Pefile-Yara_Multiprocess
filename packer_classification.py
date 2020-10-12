import os, subprocess, time
from subprocess import *            #subprocess의 Popen 함수 옵션인 PIPE가 오류가 나서 추가하였음.
from pprintpp import pprint as pp
from multiprocessing import Pool

def rule_name_list():
    readFile = open('./yara_config/packer_parser_name.txt', 'r')
    yaraPackerRuleNameList = [i.replace('\n','') for i in readFile]
    readFile.close()
    return yaraPackerRuleNameList

def packer_check(yaraCheckFilePath, fileName):
    yaraProgramPath = './yara_config/yara64.exe'
    # yaraRulePath = './yara_config/packer_rules/includePackerRules.yar'
    yaraRulePath = './yara_config/packer_rules/packer.yar'

    yaraResult = {}
    yaraResultCall = subprocess.Popen([yaraProgramPath, yaraRulePath, yaraCheckFilePath+fileName], stdout=PIPE).communicate()[0]
    yaraResultCall = yaraResultCall.decode('utf-8').split(f' {yaraCheckFilePath+fileName}\r\n')
    del yaraResultCall[-1]

    if len(yaraResultCall) == 0:
        return None

    yaraResult[yaraCheckFilePath+fileName] = yaraResultCall

    return yaraResult

def packer_forder(fileName):
    if fileName[:19] == '.\\dataset\\goodware\\':
        os.system(f'copy {fileName} .\\dataset\\gw_packing\\')
        os.system(f'rm {fileName}')
    else:
        os.system(f'copy {fileName} .\\dataset\\mw_packing\\')
        os.system(f'rm {fileName}')

if __name__ == '__main__':
    startTime = time.time()

    dir = ['.\\dataset\\goodware\\', '.\\dataset\\malware\\']
    # fileList = os.listdir(dir)

    with Pool(processes=10) as p:
        res = [p.apply_async(packer_check, args=(filePath, fileName)) for filePath in dir for fileName in os.listdir(filePath)]
        for r in res:
            if r.get() is not None:
                a = [packer_forder(fileName) for fileName in r.get().keys()]

    print(f'Time : {time.time() - startTime}')