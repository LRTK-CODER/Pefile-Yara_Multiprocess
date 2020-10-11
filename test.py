import yaraBg, cspefile, time, os
from multiprocessing import Pool
import pandas as pd

if __name__ == '__main__':
    startTime = time.time()
    
    dir = '..\\yara-bg\\dataset' # 디렉토리 설정하면 해당 디렉토리 하위까지 탐색
    result_file = '.\\save_4.csv'
    failed_extract = '.\\failed_extract'
    dir_file_list = cspefile.dir_explorer(dir)

    for file_num in range(len(dir_file_list[1][:10])):
        good_or_bad = dir_file_list[0][file_num]
        full_path = dir_file_list[1][file_num]
        vir_file = dir_file_list[2][file_num]

        yaraResult = yaraBg.test_getYaraResult(full_path, vir_file)
        print(yaraResult)

        # df_axis = pd.concat([pefileDataframe, yaraDataframe], axis=1) # column bind
        # print(df_axis)

        # if not os.path.exists(result_file):
        #     df_axis.to_csv(result_file, mode='w', index=False, encoding='utf-8-sig')
        # else:
        #     df_axis.to_csv(result_file, mode='a', index=False, header=False, encoding='utf-8-sig')

    print(f'Time : {time.time() - startTime}')