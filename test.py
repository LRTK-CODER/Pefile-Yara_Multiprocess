import yaraBg, cspefile, time, os
from multiprocessing import Pool
import pandas as pd

if __name__ == '__main__':
    startTime = time.time()
    
    dir = '.\\dataset\\malware' # 디렉토리 설정하면 해당 디렉토리 하위까지 탐색
    result_file = '.\\malware.csv'
    failed_extract = '.\\dataset\\failed_extract'
    dir_file_list = cspefile.dir_explorer(dir)

    with Pool(processes=10) as p:
        res = [
            p.apply_async(
                yaraBg.test_getYaraResult, args=( dir_file_list[1][file_num], dir_file_list[2][file_num])
            ) for file_num in range(len(dir_file_list[1]))
        ]

        for r in res:
            yaraResult = r.get()
            if not os.path.exists(result_file):
                yaraResult.to_csv(result_file, mode='w', index=True, encoding='utf-8-sig')
            else:
                yaraResult.to_csv(result_file, mode='a', index=True, header=False, encoding='utf-8-sig')

    print(f'Time : {time.time() - startTime}')