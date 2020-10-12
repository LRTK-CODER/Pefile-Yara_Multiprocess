import yaraBg, cspefile, time, os, sys
from multiprocessing import Pool
import pandas as pd
from pprintpp import pprint as pp

def file_dev(dir_file_list):
    devLenList = []
    save_dict = {}

    len_file = len(dir_file_list[1])

    if len_file %2 == 0:
        devLenList.append(int(len_file/10))
    else:
        devLenList.append(int(len_file-1/10))

    index = 2
    for i in range(8):
        devLenList.append(devLenList[0]*index)
        index += 1
    # print(devLenList) -> [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000]

    globals()['file_list_1'] = [
        [ 
            dir_file_list[0][j],
            dir_file_list[1][j], 
            dir_file_list[2][j]
        ] for j in range( 0, devLenList[0] )
    ]

    for i in range(2, 10):
        globals()[f'file_list_{i}'] = [
            [
                dir_file_list[0][j],
                dir_file_list[1][j], 
                dir_file_list[2][j]
            ] for j in range( devLenList[i-2], devLenList[i-1] )
        ]
    
    globals()['file_list_10'] = [
        [ 
            dir_file_list[0][j],
            dir_file_list[1][j], 
            dir_file_list[2][j]
        ] for j in range( devLenList[8], len_file)
    ]

    for i in range(1, 11):
        save_dict[f'.\\dataset_backup\\save{i}.csv'] = eval(f'file_list_{i}')
    
    return save_dict

def process(failed_extract, value):
    label = value[0]
    filePath = value[1]
    fileName = value[2]

    peResult = cspefile.pe_structure(failed_extract, label, filePath, fileName)

    if str(type(peResult)) == "<class 'int'>": # pefile이 터지는 경우 data_frame은 0
        return [False, fileName]

    else:
        yaraResult = yaraBg.test_getYaraResult(filePath, fileName)
        Exinfo_result = pd.concat([peResult,yaraResult],axis=1)

        return [True, Exinfo_result]


# def divide_list(l, n): 
#     # 리스트 l의 길이가 n이면 계속 반복
#     for i in range(0, len(l), n): 
#         yield l[i:i + n]

if __name__ == '__main__':
    startTime = time.time()
    
    dir = '.\\dataset_backup'
    failed_extract = '.\\dataset_backup\\failed_extract'

    dir_file_list = list(cspefile.dir_explorer(dir))
    save_dict = file_dev(dir_file_list)

    with Pool(processes=10) as p:
        totalCsvExtraction = []

        # for key in list(save_dict.keys())[3:5]:      #키 설정해서 test
        for key in save_dict.keys():
            print(f'{ key[ 17 :  ] } >>> {len(save_dict[key])} 개 추출 시작.')
            index = 1
            res = [p.apply_async(process, args=(failed_extract, value)) for value in save_dict[key]]

            for r in res:
                boolValue = r.get()[0]
                returnRsult = r.get()[1]

                if boolValue is False:
                    print('\033[95m' + f'{returnRsult} >>> 추출 실패.' + '\033[0m')
                    
                else:
                    if not os.path.exists(key):
                        returnRsult.to_csv(key, mode='w', index=False, encoding='utf-8-sig')
                        # print(f'{ key[ 17 :  ] } >>> [{index} / {len(save_dict[key])}] 개 추출 완료.')
                    
                    else:
                        returnRsult.to_csv(key, mode='a',index=False, header= False, encoding='utf-8-sig')
                        # print(f'{ key[ 17 :  ] } >>> [{index} / {len(save_dict[key])}] 개 추출 완료.')
                    
                    index += 1
            
            print(f'{ key[ 17 :  ] } >>> [{index-1} / {len(save_dict[key])}] 개 추출 완료.\n' + '='*100)
            totalCsvExtraction.append(index-1)
        
        print('\n\n'+ '='*100)
        for key, total in zip(list(save_dict.keys()), totalCsvExtraction):
            print(f'{key[ 17 : ]} ==> total : {total} / {len(save_dict[key])} 개, exception : {len(save_dict[key]) - total}' )
        print('='*100)

    print(f'Time : {time.time() - startTime}')