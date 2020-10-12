import pefile
import struct
import datetime
import os
import pandas as pd
import numpy as np
import hashlib as hl
from pyprnt import prnt
from pprintpp import pprint as pp
import time
import multiprocessing as mp

__dos_h_format__ = ('IMAGE_DOS_HEADER',
    (
    # 'e_magic', 
    'e_cblp', 
    'e_cp',
    # 'e_crlc', 
    # 'e_cparhdr', 
    'e_minalloc',
    # 'e_maxalloc', 
    # 'e_ss', 
    # 'e_sp', 
    # 'e_csum',
    # 'e_ip', 
    # 'e_cs', 
    # 'e_lfarlc', 
    'e_ovno', 
    # 'e_res',
    # 'e_oemid', 
    # 'e_oeminfo', 
    # 'e_res2',
    'e_lfanew'
    ))
    
__nt_h_format__ = ('IMAGE_NT_HEADERS', ('Signature'))

__file_h_format__ = ('IMAGE_FILE_HEADER',
        ('Machine', 
        'NumberOfSections',
        # 'TimeDateStamp', 
        'PointerToSymbolTable',
        'NumberOfSymbols', 
        'SizeOfOptionalHeader',
        # 'Characteristics'
        ))

__file_h_characteristics__ = {
    'IMAGE_FILE_RELOCS_STRIPPED':          0x0001,
    'IMAGE_FILE_EXECUTABLE_IMAGE':         0x0002,
    'IMAGE_FILE_LINE_NUMS_STRIPPED':       0x0004,
    'IMAGE_FILE_LOCAL_SYMS_STRIPPED':      0x0008,
    'IMAGE_FILE_AGGRESIVE_WS_TRIM':        0x0010,
    'IMAGE_FILE_LARGE_ADDRESS_AWARE':      0x0020,
    'IMAGE_FILE_16BIT_MACHINE':            0x0040,
    'IMAGE_FILE_BYTES_REVERSED_LO':        0x0080,
    'IMAGE_FILE_32BIT_MACHINE':            0x0100,
    'IMAGE_FILE_DEBUG_STRIPPED':           0x0200,
    'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP':  0x0400,
    'IMAGE_FILE_NET_RUN_FROM_SWAP':        0x0800,
    'IMAGE_FILE_SYSTEM':                   0x1000,
    'IMAGE_FILE_DLL':                      0x2000,
    'IMAGE_FILE_UP_SYSTEM_ONLY':           0x4000,
    'IMAGE_FILE_BYTES_REVERSED_HI':        0x8000}

__machine_types__ = {
    'IMAGE_FILE_MACHINE_UNKNOWN':  0,
    'IMAGE_FILE_MACHINE_I386':     0x014c,
    'IMAGE_FILE_MACHINE_R3000':    0x0162,
    'IMAGE_FILE_MACHINE_R4000':    0x0166,
    'IMAGE_FILE_MACHINE_R10000':   0x0168,
    'IMAGE_FILE_MACHINE_WCEMIPSV2':0x0169,
    'IMAGE_FILE_MACHINE_ALPHA':    0x0184,
    'IMAGE_FILE_MACHINE_SH3':      0x01a2,
    'IMAGE_FILE_MACHINE_SH3DSP':   0x01a3,
    'IMAGE_FILE_MACHINE_SH3E':     0x01a4,
    'IMAGE_FILE_MACHINE_SH4':      0x01a6,
    'IMAGE_FILE_MACHINE_SH5':      0x01a8,
    'IMAGE_FILE_MACHINE_ARM':      0x01c0,
    'IMAGE_FILE_MACHINE_THUMB':    0x01c2,
    'IMAGE_FILE_MACHINE_ARMNT':    0x01c4,
    'IMAGE_FILE_MACHINE_AM33':     0x01d3,
    'IMAGE_FILE_MACHINE_POWERPC':  0x01f0,
    'IMAGE_FILE_MACHINE_POWERPCFP':0x01f1,
    'IMAGE_FILE_MACHINE_IA64':     0x0200,
    'IMAGE_FILE_MACHINE_MIPS16':   0x0266,
    'IMAGE_FILE_MACHINE_ALPHA64':  0x0284,
    'IMAGE_FILE_MACHINE_AXP64':    0x0284, # same
    'IMAGE_FILE_MACHINE_MIPSFPU':  0x0366,
    'IMAGE_FILE_MACHINE_MIPSFPU16':0x0466,
    'IMAGE_FILE_MACHINE_TRICORE':  0x0520,
    'IMAGE_FILE_MACHINE_CEF':      0x0cef,
    'IMAGE_FILE_MACHINE_EBC':      0x0ebc,
    'IMAGE_FILE_MACHINE_AMD64':    0x8664,
    'IMAGE_FILE_MACHINE_M32R':     0x9041,
    'IMAGE_FILE_MACHINE_CEE':      0xc0ee}       

__optional_h_format__ = ('IMAGE_OPTIONAL_HEADER',
        ('Magic', 'MajorLinkerVersion',
        'MinorLinkerVersion', 'SizeOfCode',
        'SizeOfInitializedData', 'SizeOfUninitializedData',
        'AddressOfEntryPoint', 'BaseOfCode',
        'ImageBase', 'SectionAlignment', 'FileAlignment',
        'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
        'MajorImageVersion', 'MinorImageVersion',
        'MajorSubsystemVersion', 'MinorSubsystemVersion',
        'Reserved1', 'SizeOfImage', 'SizeOfHeaders',
        'CheckSum', 'Subsystem', #'DllCharacteristics',
        'SizeOfStackReserve', 'SizeOfStackCommit',
        'SizeOfHeapReserve', 'SizeOfHeapCommit',
        'LoaderFlags', 'NumberOfRvaAndSizes', 'BaseOfData'))
        
__optional_h64_format__ = ('IMAGE_OPTIONAL_HEADER',
        ('Magic', 'MajorLinkerVersion',
        'MinorLinkerVersion', 'SizeOfCode',
        'SizeOfInitializedData', 'SizeOfUninitializedData',
        'AddressOfEntryPoint', 'BaseOfCode',
        'ImageBase', 'SectionAlignment', 'FileAlignment',
        'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
        'MajorImageVersion', 'MinorImageVersion',
        'MajorSubsystemVersion', 'MinorSubsystemVersion',
        'Reserved1', 'SizeOfImage', 'SizeOfHeaders',
        'CheckSum', 'Subsystem', #'DllCharacteristics',
        'SizeOfStackReserve', 'SizeOfStackCommit',
        'SizeOfHeapReserve', 'SizeOfHeapCommit',
        'LoaderFlags', 'NumberOfRvaAndSizes' ))
        
__section_h_format__ = ('IMAGE_SECTION_HEADER',
        ('Misc', 'Misc_PhysicalAddress','Misc_VirtualSize',
        'VirtualAddress', 'SizeOfRawData', 'PointerToRawData',
        'PointerToRelocations', 'PointerToLinenumbers',
        'NumberOfRelocations', 'NumberOfLinenumbers',
        'Characteristics'))

__directory_entry_types__ = {
    'IMAGE_DIRECTORY_ENTRY_EXPORT':        0,
    'IMAGE_DIRECTORY_ENTRY_IMPORT':        1,
    'IMAGE_DIRECTORY_ENTRY_RESOURCE':      2,
    'IMAGE_DIRECTORY_ENTRY_EXCEPTION':     3,
    'IMAGE_DIRECTORY_ENTRY_SECURITY':      4,
    'IMAGE_DIRECTORY_ENTRY_BASERELOC':     5,
    'IMAGE_DIRECTORY_ENTRY_DEBUG':         6,
    'IMAGE_DIRECTORY_ENTRY_COPYRIGHT':     7,
    'IMAGE_DIRECTORY_ENTRY_GLOBALPTR':     8,
    'IMAGE_DIRECTORY_ENTRY_TLS':           9,
    'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG':   10,
    'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT':  11,
    'IMAGE_DIRECTORY_ENTRY_IAT':           12,
    'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT':  13,
    'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR':14,
    'IMAGE_DIRECTORY_ENTRY_RESERVED':      15}

__section_characteristics__ = [
    ('IMAGE_SCN_TYPE_REG',                  0x00000000), # reserved
    ('IMAGE_SCN_TYPE_DSECT',                0x00000001), # reserved
    ('IMAGE_SCN_TYPE_NOLOAD',               0x00000002), # reserved
    ('IMAGE_SCN_TYPE_GROUP',                0x00000004), # reserved
    ('IMAGE_SCN_TYPE_NO_PAD',               0x00000008), # reserved
    ('IMAGE_SCN_TYPE_COPY',                 0x00000010), # reserved

    ('IMAGE_SCN_CNT_CODE',                  0x00000020),
    ('IMAGE_SCN_CNT_INITIALIZED_DATA',      0x00000040),
    ('IMAGE_SCN_CNT_UNINITIALIZED_DATA',    0x00000080),

    ('IMAGE_SCN_LNK_OTHER',                 0x00000100),
    ('IMAGE_SCN_LNK_INFO',                  0x00000200),
    ('IMAGE_SCN_LNK_OVER',                  0x00000400), # reserved
    ('IMAGE_SCN_LNK_REMOVE',                0x00000800),
    ('IMAGE_SCN_LNK_COMDAT',                0x00001000),

    ('IMAGE_SCN_MEM_PROTECTED',             0x00004000), # obsolete
    ('IMAGE_SCN_NO_DEFER_SPEC_EXC',         0x00004000),
    ('IMAGE_SCN_GPREL',                     0x00008000),
    ('IMAGE_SCN_MEM_FARDATA',               0x00008000),
    ('IMAGE_SCN_MEM_SYSHEAP',               0x00010000), # obsolete
    ('IMAGE_SCN_MEM_PURGEABLE',             0x00020000),
    ('IMAGE_SCN_MEM_16BIT',                 0x00020000),
    ('IMAGE_SCN_MEM_LOCKED',                0x00040000),
    ('IMAGE_SCN_MEM_PRELOAD',               0x00080000),

    ('IMAGE_SCN_ALIGN_1BYTES',              0x00100000),
    ('IMAGE_SCN_ALIGN_2BYTES',              0x00200000),
    ('IMAGE_SCN_ALIGN_4BYTES',              0x00300000),
    ('IMAGE_SCN_ALIGN_8BYTES',              0x00400000),
    ('IMAGE_SCN_ALIGN_16BYTES',             0x00500000), # default alignment
    ('IMAGE_SCN_ALIGN_32BYTES',             0x00600000),
    ('IMAGE_SCN_ALIGN_64BYTES',             0x00700000),
    ('IMAGE_SCN_ALIGN_128BYTES',            0x00800000),
    ('IMAGE_SCN_ALIGN_256BYTES',            0x00900000),
    ('IMAGE_SCN_ALIGN_512BYTES',            0x00A00000),
    ('IMAGE_SCN_ALIGN_1024BYTES',           0x00B00000),
    ('IMAGE_SCN_ALIGN_2048BYTES',           0x00C00000),
    ('IMAGE_SCN_ALIGN_4096BYTES',           0x00D00000),
    ('IMAGE_SCN_ALIGN_8192BYTES',           0x00E00000),
    ('IMAGE_SCN_ALIGN_MASK',                0x00F00000),

    ('IMAGE_SCN_LNK_NRELOC_OVFL',           0x01000000),
    ('IMAGE_SCN_MEM_DISCARDABLE',           0x02000000),
    ('IMAGE_SCN_MEM_NOT_CACHED',            0x04000000),
    ('IMAGE_SCN_MEM_NOT_PAGED',             0x08000000),
    ('IMAGE_SCN_MEM_SHARED',                0x10000000),
    ('IMAGE_SCN_MEM_EXECUTE',               0x20000000),
    ('IMAGE_SCN_MEM_READ',                  0x40000000),
    ('IMAGE_SCN_MEM_WRITE',                 0x80000000) ]

__dll_characteristics__ = {
     'IMAGE_LIBRARY_PROCESS_INIT':                     0x0001, # reserved
     'IMAGE_LIBRARY_PROCESS_TERM':                     0x0002, # reserved
     'IMAGE_LIBRARY_THREAD_INIT':                      0x0004, # reserved
     'IMAGE_LIBRARY_THREAD_TERM':                      0x0008, # reserved
     'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA':       0x0020,
     'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE':          0x0040,
     'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY':       0x0080,
     'IMAGE_DLLCHARACTERISTICS_NX_COMPAT':             0x0100,
     'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION':          0x0200,
     'IMAGE_DLLCHARACTERISTICS_NO_SEH':                0x0400,
     'IMAGE_DLLCHARACTERISTICS_NO_BIND':               0x0800,
     'IMAGE_DLLCHARACTERISTICS_APPCONTAINER':          0x1000,
     'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER':            0x2000,
     'IMAGE_DLLCHARACTERISTICS_GUARD_CF':              0x4000,
     'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE': 0x8000}
     
__import_desc_format__ =  ('IMAGE_IMPORT_DESCRIPTOR',
        ('OriginalFirstThunk','Characteristics',
         'TimeDateStamp', 'ForwarderChain', 'Name', 'FirstThunk'))

__delay_import_desc_format__ = ('IMAGE_DELAY_IMPORT_DESCRIPTOR',
        ('grAttrs', 'szName', 'phmod', 'pIAT', 'pINT',
        'pBoundIAT', 'pUnloadIAT', 'dwTimeStamp'))
        
__tls_dir_format__ = ('IMAGE_TLS_DIRECTORY',
        ('StartAddressOfRawData', 'EndAddressOfRawData',
        'AddressOfIndex', 'AddressOfCallBacks',
        'SizeOfZeroFill', 'Characteristics' ) )
        
__load_cfg_dir_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY',
        ('Size',
        'TimeDateStamp',
        'MajorVersion',
        'MinorVersion',
        'GlobalFlagsClear',
        'GlobalFlagsSet',
        'CriticalSectionDefaultTimeout',
        'DeCommitFreeBlockThreshold',
        'DeCommitTotalFreeThreshold',
        'LockPrefixTable',
        'MaximumAllocationSize',
        'VirtualMemoryThreshold',
        'ProcessHeapFlags',
        'ProcessAffinityMask',
        'CSDVersion',
        'Reserved1',
        'EditList',
        'SecurityCookie',
        'SEHandlerTable',
        'SEHandlerCount',
        'GuardCFCheckFunctionPointer',
        'Reserved2',
        'GuardCFFunctionTable',
        'GuardCFFunctionCount',
        'GuardFlags' ) )
        
__dbg_dir_format__ = ('IMAGE_DEBUG_DIRECTORY',
        ('Characteristics', 'TimeDateStamp', 'MajorVersion',
        'MinorVersion', 'SizeOfData', 'AddressOfRawData',
        'PointerToRawData'))
        
__functions__ = ['dos_h(pe,dic)',
                 # 'nt_h(pe,dic)',
                 'file_h(pe,dic)',
                 'optional_h(pe,dic)',
                 # 'import_desc(pe,dic)',
                 # 'delay_import_desc(pe,dic)',
                 'section_h(pe,dic)',
                 'tls_dir(pe,dic)',
                 'data_dir(pe,dic)'
                 # 'load_cfg(pe,dic)',
                 # 'debug_info(pe,dic)'
                 ]

def get_md5(filename):
    md5 = hl.md5()
    
    with open(filename, 'rb') as afile:
        buf = afile.read()
        md5.update(buf)

    return md5.hexdigest()

def dos_h(pe,dic) :
    title = 'DOS HEADER INFO\n'
    form =  'dic[\'DOS_HEADER\'][field][\'{}\']'                       # dict 자료형으로 저장 된 값 추출 형식 지정
    
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장

    for field in __dos_h_format__[1]:
        offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                        hex(eval(form.format('Offset')))])         # 지역 offset 추출  
        data_dict['[DH]'+field] =  hex(eval(form.format('Value')))             # {필드명 : 값} 형태로 dict 자료형으로 저장 


    printer(title, offsets, data_dict)
    return data_dict

def nt_h(pe,dic) :
    title = 'NT HEADERS INFO\n'
    form = 'dic[\'NT_HEADERS\'][\'Signature\'][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                    hex(eval(form.format('Offset')))])         # 지역 offset 추출  
    data_dict['[NH]'+'Signature'] = hex(eval(form.format('Value')))             # {필드명 : 값} 형태로 dict 자료형으로 저장 
    
    printer(title, offsets, data_dict)
    
    return data_dict

def file_h(pe,dic) :
    title = 'FILE HEADER INFO\n'
    form = 'dic[\'FILE_HEADER\'][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    for field in __file_h_format__[1]:
            offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                            hex(eval(form.format('Offset')))])         # 지역 offset 추출  
            data_dict['[FH]'+field] =  eval(form.format('Value'))             # {필드명 : 값} 형태로 dict 자료형으로 저장 
    
    for i in __file_h_characteristics__.keys() :
        if i in dic['Flags']:
            offsets.append(['none','none'])
            data_dict['[FH_C]'+i.lstrip('IMAGE_')] = '1'
        else :
            offsets.append(['none','none'])
            data_dict['[FH_C]'+i.lstrip('IMAGE_')] = '0'
    
    printer(title, offsets, data_dict)
    
    return data_dict

def optional_h(pe,dic) :
    title = 'OPTIONAL HEADER INFO\n'
    form = 'dic[\'OPTIONAL_HEADER\'][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    if dic['OPTIONAL_HEADER']['Magic']['Value'] == 0x10b :
        for field in __optional_h_format__[1]:
                offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                                hex(eval(form.format('Offset')))])         # 지역 offset 추출  
                data_dict['[OH]'+field] =  hex(eval(form.format('Value')))             # {필드명 : 값} 형태로 dict 자료형으로 저장 

    else :
        for field in __optional_h64_format__[1]:
                offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                                hex(eval(form.format('Offset')))])         # 지역 offset 추출  
                data_dict['[OH]'+field] =  hex(eval(form.format('Value')))             # {필드명 : 값} 형태로 dict 자료형으로 저장 
        offsets.append(['none','none'])
        data_dict['[OH]BaseOfData'] = '0'

    for i in __dll_characteristics__.keys() :
        if i in dic['DllCharacteristics']:
            offsets.append(['none','none'])
            data_dict['[OH_C]'+i.lstrip('IMAGE_')] = '1'
        else :
            offsets.append(['none','none'])
            data_dict['[OH_C]'+i.lstrip('IMAGE_')] = '0'  
            
    printer(title, offsets, data_dict)
    
    return data_dict

def data_dir(pe,dic) : ############### tls만 살려!!!!!!!!!!!!~!
    title = 'DIRECTORIES INFO\n'
    form = 'dic[\'Directories\'][i][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장

    for tls in dic['Directories']:   
        if tls['Structure'] == 'IMAGE_DIRECTORY_ENTRY_TLS':
            offsets.append([hex(tls['VirtualAddress']['FileOffset']),
                            hex(tls['VirtualAddress']['Offset'])])
            data_dict['[DIR]'+'{}'.format(tls['Structure'].lstrip('IMAGE_'))] = hex(tls['VirtualAddress']['Value'])  # {필드명 : 값} 형태로 dict 자료형으로 저장
            break
    
    
    printer(title, offsets, data_dict)
    
    return data_dict

def import_desc(pe,dic): # 함수별 hint값 추출 필요여부 조사
    # print(list(dic['Imported symbols'][1][1].keys())[1])
    # input('')
    # os.system('cls')
    # print('desc갯수>>>',len(dic['Imported symbols']))
    # for i in range(len(dic['Imported symbols'])):
        # for j in range(len(dic['Imported symbols'][i])):
            # print('i({0})j({1})>>>'.format(i,j),dic['Imported symbols'][i][j])
            # print('')

    title = 'IMPORT DESCRIPTOR INFO\n'
    form = 'dic[\'Imported symbols\'][i][0][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    key = 'list(dic[\'Imported symbols\'][i][j].keys())[1]'
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    offsets.append(['none','none'])
    data_dict['[IM]NumberOfImportDlls'] = len(dic['Imported symbols'])
    for i in range(len(dic['Imported symbols'])):
        for j in range(len(dic['Imported symbols'][i])):
            #data_dict['({})'.format(dic['Imported symbols'][i][1]['DLL'].decode('utf-8'))] = 
            if j == 0 :
                for field in __import_desc_format__[1]:
                    offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                                    hex(eval(form.format('Offset')))])         # 지역 offset 추출  
                    data_dict['[IM]({})'.format(dic['Imported symbols'][i][1]['DLL'].decode('utf-8'))+field] = eval(form.format('Value'))  # {필드명 : 값} 형태로 dict 자료형으로 저장 
            else :
                offsets.append(['none','none'])
                data_dict['[IM_F]({})'.format(dic['Imported symbols'][i][1]['DLL'].decode('utf-8'))+'func_'+str(j)] = str(dic['Imported symbols'][i][j][eval(key)]).lstrip('b\'').rstrip('\'')

    printer(title, offsets, data_dict)

    return data_dict
    
def delay_import_desc(pe,dic): # 함수별 hint값 및 bound값 추출 필요여부 조사
    # print('desc갯수>>>',len(dic['Delay Imported symbols']))
    # for i in range(len(dic['Delay Imported symbols'])):
        # for j in range(len(dic['Delay Imported symbols'][i])):
            # print('i({0})j({1})>>>'.format(i,j),dic['Delay Imported symbols'][i][j])
            # print('')

    title = 'DELAY IMPORT DESCRIPTOR INFO\n'
    form = 'dic[\'Delay Imported symbols\'][i][0][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    key = 'list(dic[\'Delay Imported symbols\'][i][j].keys())[1]'
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    offsets.append(['none','none'])
    data_dict['[D_IM]NumberOfDelayImportDlls'] = len(dic['Delay Imported symbols'])
    for i in range(len(dic['Delay Imported symbols'])):
        for j in range(len(dic['Delay Imported symbols'][i])):
            #data_dict['({})'.format(dic['Delay Imported symbols'][i][1]['DLL'].decode('utf-8'))] = 
            if j == 0 :
                for field in __delay_import_desc_format__[1]:
                    offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                                    hex(eval(form.format('Offset')))])         # 지역 offset 추출  
                    data_dict['[D_IM]({})'.format(dic['Delay Imported symbols'][i][1]['DLL'].decode('utf-8'))+field] = eval(form.format('Value'))  # {필드명 : 값} 형태로 dict 자료형으로 저장 
            else :
                offsets.append(['none','none'])
                data_dict['[D_IM]({})'.format(dic['Delay Imported symbols'][i][1]['DLL'].decode('utf-8'))+'func_'+str(j)] = str(dic['Delay Imported symbols'][i][j][eval(key)]).lstrip('b\'').rstrip('\'')

    printer(title, offsets, data_dict)
    
    return data_dict

def section_h_BAK(pe,dic) :
    title = 'SECTION HEADER INFO\n'
    form = 'dic[\'PE Sections\'][i][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    form_ = 'dic[\'PE Sections\'][i][\'Name\'][\'Value\']'
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장

    offsets.append(['none','none'])
    data_dict['[SH]NumberOfSections'] = len(dic['PE Sections'])
    for i in range(len(dic['PE Sections'])):
        offsets.append(['none','none'])
        data_dict['[SH]({})'.format(eval(form_).rstrip('\\x00')) + 'Name'] = eval(form_.format('Value')).rstrip('\\x00')
        for field in __section_h_format__[1]:
            offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                            hex(eval(form.format('Offset')))])         # 지역 offset 추출  
            data_dict['[SH]({})'.format(eval(form_).rstrip('\\x00')) + field] = eval(form.format('Value'))                  # {필드명 : 값} 형태로 dict 자료형으로 저장 
        offsets.append(['none','none'])
        data_dict['[SH]({})'.format(eval(form_).rstrip('\\x00'))+'Entropy'] = dic['PE Sections'][i]['Entropy']
    # printer(title, offsets, data_dict)
# '''        
        cr_value = data_dict['[SH]({})'.format(eval(form_).rstrip('\\x00')) + 'Characteristics']
        bit_weight = []
        
        for j in range(0, 32) : # __section_characteristics__는 32비트로 구성되어 있음.
            bit_weight.append(cr_value & ( 1 << j ))
        bit_weight = list(set(bit_weight))
        del bit_weight[0]
        
# print('__section_characteristics__의 크기 =',len(__section_characteristics__))
        # print('>>>',bit_weight) 
        for k in range(0,len(__section_characteristics__)) :
            for l in range(0,len(bit_weight)) :
                # print('현재 k = ',k,'현재 l = ',l)
                if __section_characteristics__[k][1] == bit_weight[l] :
                    offsets.append(['none','none'])
                    # print('k={}, (1)>>>'.format(k),__section_characteristics__[k][0])
                    data_dict['[SH_C]({})'.format(eval(form_).rstrip('\\x00')) + __section_characteristics__[k][0]] = '1'
##                   print('>>>',l,len(bit_weight)-1)
                    break
                elif l == len(bit_weight)-1 :
                    offsets.append(['none','none'])
                    # print('k={}, (0)>>>'.format(k),__section_characteristics__[k][0])
                    data_dict['[SH_C]({})'.format(eval(form_).rstrip('\\x00')) + __section_characteristics__[k][0]] = '0'
# '''                   
    printer(title, offsets, data_dict)
    
    return data_dict

def section_h(pe,dic) :
    section_type = {'.text':['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ'],
                    '.itext':['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ'],
                    '.rdata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'],
                    '.data':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.rsrc':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'],
                    '.reloc':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_READ'],
                    '.bss':['IMAGE_SCN_CNT_UNINITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.cormeta':['IMAGE_SCN_LNK_INFO'],
                    '.debug$F':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_READ'],
                    '.debug$P':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_READ'],
                    '.debug$S':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_READ'],
                    '.debug$T':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_READ'],
                    '.drective':['IMAGE_SCN_LNK_INFO'],
                    '.edat':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'],
                    '.idata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.idlsym':['IMAGE_SCN_LNK_INFO'],
                    '.pdata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'],
                    '.sbss':['IMAGE_SCN_CNT_UNINITIALIZED_DATA', 'IMAGE_SCN_MEM_FARDATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.sdata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_FARDATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.srdata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_FARDATA', 'IMAGE_SCN_MEM_READ'],
                    '.sxdata':['IMAGE_SCN_LNK_INFO'],
                    '.tls':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.tls$':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'],
                    '.vsdata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ',  'IMAGE_SCN_MEM_WRITE'],
                    '.xdata':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'],
                    '.didat':['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE']
    }
    title = 'SECTION HEADER INFO\n'
    form = 'dic[\'PE Sections\'][i][\'Characteristics\'][\'Value\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    form_ = 'dic[\'PE Sections\'][i][\'Name\'][\'Value\']'
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    c_sec = 0

    
    for i in range(len(dic['PE Sections'])):
        characteristics = []
        section_name = eval(form_).rstrip('\\x00')
        section_characteristics = eval(form)
 
        cr_value = section_characteristics
        bit_weight = []
        align_bytes = 0
        
        for j in range(0, 32) : # __section_characteristics__는 32비트로 구성되어 있음.
            if j >= 20 and j <= 22:
                align_bytes += cr_value & ( 1 << j )
            elif j == 23:
                align_bytes += cr_value & ( 1 << j )
                bit_weight.append(align_bytes)
            else:
                bit_weight.append(cr_value & ( 1 << j ))
        
            bit_weight = list(set(bit_weight))
        del bit_weight[0]
        
        # print('bit_weight >>>')                   # Flag비트 값 정상 출력 확인용
        # for zzz in range(len(bit_weight)):
            # print(hex(bit_weight[zzz]),end=' ')
            
        for k in range(0,len(__section_characteristics__)) :
            for l in range(0,len(bit_weight)) :
                if __section_characteristics__[k][1] == bit_weight[l] :
                    characteristics.append(__section_characteristics__[k][0])
                    break
        
        if section_name in section_type.keys():
            for flag in characteristics:
                if flag in section_type[section_name]:
                    continue
                else:
                    ##############################################################################
                    # print('\n[{}] Section is Corrupted. >>>'.format(section_name),section_name)
                    # print('Characteristics >>>',cr_value)
                    # print('{} Flags >>>'.format(section_name))                    # 내가 만든 함수가 출력한 section characteristics flags
                    # pp(characteristics)
                    
                    # print('\npefile module\'s printed >>>') # pefile모듈이 출력한 section characteristics flags 결과가 부정확하다.
                    # pp(dic['PE Sections'][i]['Flags'])
                    ##############################################################################
                    c_sec += 1
                    break
                    
    if c_sec == 0 :
        data_dict['[SH]SectionCorrupted'] = 0         # 정상
    else :
        data_dict['[SH]SectionCorrupted'] = c_sec
    offsets.append(['none','none'])
        
    printer(title, offsets, data_dict)

    return data_dict

def tls_dir_BAK(pe,dic):
    title = 'TLS DIRECTORIES INFO\n'
    form = 'dic[\'TLS\'][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    for field in __tls_dir_format__[1]:
        offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                        hex(eval(form.format('Offset')))])         # 지역 offset 추출  
        data_dict['[TLS]'+field] = hex(eval(form.format('Value')))  # {필드명 : 값} 형태로 dict 자료형으로 저장 
    
    printer(title, offsets, data_dict)
    
    return data_dict
    
def tls_dir(pe,dic):
    title = 'TLS DIRECTORIES INFO\n'
    form = 'dic[\'TLS\'][\'AddressOfCallBacks\'][\'Value\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    try:
        data_dict['[TLS]AddressOfCallBacks'] = hex(eval(form))  # {필드명 : 값} 형태로 dict 자료형으로 저장 
        offsets.append(['none','none'])
    except:
        data_dict['[TLS]AddressOfCallBacks'] = 0  # {필드명 : 값} 형태로 dict 자료형으로 저장 
        offsets.append(['none','none'])
        
    printer(title, offsets, data_dict)
    
    return data_dict
    
def load_cfg(pe,dic):
    title = 'LOAD CONFIG INFO\n'
    form = 'dic[\'LOAD_CONFIG\'][field][\'{}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    for field in __load_cfg_dir_format__[1]:
        offsets.append([hex(eval(form.format('FileOffset'))),      # 전역 offset 추출
                        hex(eval(form.format('Offset')))])         # 지역 offset 추출  
        data_dict['[LC]'+field] = eval(form.format('Value'))  # {필드명 : 값} 형태로 dict 자료형으로 저장 
    
    printer(title, offsets, data_dict)
    
    return data_dict
    
def debug_info(pe,dic): # 함수별 hint값 추출 필요여부 조사
    title = 'DEBUG INFO\n'
    form = 'pe.DIRECTORY_ENTRY_DEBUG[i].{0}.dump_dict()[field][\'{1}\']'         # dict 자료형으로 저장 된 값 추출 형식 지정
    offsets = []    # offsets값 저장
    data_dict = {}  # 필드명 : 값 형태로 저장
    
    offsets.append(['none','none'])
    data_dict['[DBG]NumberOfDebugDirectories'] = len(dic['Debug information'])
    for i in range(len(pe.DIRECTORY_ENTRY_DEBUG)):
            for field in __dbg_dir_format__[1]:
                offsets.append(['none','none'])
                data_dict['[DBG]({})Type'.format(i+1)] = dic['Debug information'][i]['Type']
                offsets.append([hex(eval(form.format('struct','FileOffset'))),      # 전역 offset 추출
                                hex(eval(form.format('struct','Offset')))])         # 지역 offset 추출  
                data_dict['[DBG]({})'.format(i+1)+field] = eval(form.format('struct','Value'))
                
            if pe.DIRECTORY_ENTRY_DEBUG[i].entry is not None:
                keys_ = pe.DIRECTORY_ENTRY_DEBUG[i].entry.dump_dict().keys()
                for field in keys_:
                    if field == 'Structure':
                        offsets.append(['none','none'])
                        data_dict['[DBG]({0})({1})'.format(i+1,pe.DIRECTORY_ENTRY_DEBUG[i].entry.dump_dict()['Structure'])+field] = pe.DIRECTORY_ENTRY_DEBUG[i].entry.dump_dict()['Structure']
                    else:
                        offsets.append([hex(eval(form.format('entry','FileOffset'))),      # 전역 offset 추출
                                        hex(eval(form.format('entry','Offset')))])
                        data_dict['[DBG]({0})({1})'.format(i+1,pe.DIRECTORY_ENTRY_DEBUG[i].entry.dump_dict()['Structure'])+field] = eval(form.format('entry','Value'))
            else:
                continue
            
    printer(title, offsets, data_dict)
    
    return data_dict
    
def get_keys() :
    dic = pe.dump_dict()
    print(list(dic.keys()))
          
def test(pe,dic):
    # filename = "ModernWarfare.exe"
    # start_time = time.time()
    # pe = pefile.PE(filename) 
    # dic = pe.dump_dict()
    #################
        # for i in range(len(pe.DIRECTORY_ENTRY_RESOURCE.entries)): # 리소스 디렉토리 갯수 파악
        # print(pe.DIRECTORY_ENTRY_RESOURCE.entries[i].directory.struct)
    
    # pp(dic['Resource directory']) # prnt(dic['Resource directory']) 
    # print(pe.get_resources_strings())
#################
    '''
    a = pe.OPTIONAL_HEADER
    print('keys:\n',a.__keys__,'\n')
    print(a)

    for i in a.__keys__ :
            print(hex(a.__field_offsets__[i[0]] + a.__file_offset__),hex(a.__field_offsets__[i[0]]),'{}'.format(i[0]),hex(eval('a.{}'.format(i[0]))))
    '''
##################
####
    # directory_parsing = (
            # ('IMAGE_DIRECTORY_ENTRY_IMPORT', pe.parse_import_directory),
            # ('IMAGE_DIRECTORY_ENTRY_EXPORT', pe.parse_export_directory),
            # ('IMAGE_DIRECTORY_ENTRY_RESOURCE', pe.parse_resources_directory),
            # ('IMAGE_DIRECTORY_ENTRY_DEBUG', pe.parse_debug_directory),
            # ('IMAGE_DIRECTORY_ENTRY_BASERELOC', pe.parse_relocations_directory),
            # ('IMAGE_DIRECTORY_ENTRY_TLS', pe.parse_directory_tls),
            # ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', pe.parse_directory_load_config),
            # ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', pe.parse_delay_import_directory),
            # ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', pe.parse_directory_bound_imports) )
            
    # directory_parsing[n][1](인자) # 이렇게 함수를 호출할 수도 있다!
#### 
    print('리소스 디렉토리 갯수>>>',len(pe.DIRECTORY_ENTRY_RESOURCE.entries),'\n')

    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.name is not None:
            print('디렉토리 이름>>>',resource_type.name)
        else:
            print('디렉토리 이름>>>',resource_type.struct.Id, pefile.RESOURCE_TYPE.get(resource_type.struct.Id, '-'))
        print(' 리소스 갯수>>>',len(resource_type.directory.entries))
        
        for resource_id in resource_type.directory.entries:
            if resource_id.name is not None:
                print('     리소스 name -',resource_id.name)
            else:
                print('     리소스 id -',resource_id.struct.Id)
        print('')
    print('')
    
    for i in range(len(dic['Resource directory'])):
        if str(type(dic['Resource directory'][i])) == '<class \'list\'>':
            for j in range(len(dic['Resource directory'][i])) :
                if str(type(dic['Resource directory'][i][j])) == '<class \'list\'>':
                    for k in range(len(dic['Resource directory'][i][j])) :
                        print(type(dic['Resource directory'][i][j][k]))
                        # print('[i({0})j({1})k({2})] >>> {3}\n'.format(i,j,k,dic['Resource directory'][i][j][k]['Structure']),end='')
                        print('[i({0})j({1})k({2})] >>> {3}\n'.format(i,j,k,dic['Resource directory'][i][j][k]),end='')
                        pp(dic['Resource directory'][i][j][k])
                        print('')
                else:
                    print(type(dic['Resource directory'][i][j]))
                    print('[i({0})j({1})] >>> {2}\n'.format(i,j,dic['Resource directory'][i][j]['Structure']),end='')
                    pp(dic['Resource directory'][i][j])
                    print('')
        else:
            print(type(dic['Resource directory'][i]))
            print('[i({0})] >>> {1}\n'.format(i,dic['Resource directory'][i]['Structure']),end='')
            pp(dic['Resource directory'][i])
            print('')
        ## input('')
    end_time = time.time()
    print('소요시간>>>',end_time-start_time)  

def test_BAK(pe,dic):
    print('리소스 디렉토리 갯수>>>',len(pe.DIRECTORY_ENTRY_RESOURCE.entries),'\n')

    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.name is not None:
            print('디렉토리 이름>>>',resource_type.name)
        else:
            print('디렉토리 이름>>>',resource_type.struct.Id, pefile.RESOURCE_TYPE.get(resource_type.struct.Id, '-'))
        print(' 리소스 갯수>>>',len(resource_type.directory.entries))
        
        for resource_id in resource_type.directory.entries:
            if resource_id.name is not None:
                print('     리소스 name -',resource_id.name)
            else:
                print('     리소스 id -',resource_id.struct.Id)
        print('')
    print('')
    
    for i in range(len(dic['Resource directory'])):
        if str(type(dic['Resource directory'][i])) == '<class \'list\'>':
            for j in range(len(dic['Resource directory'][i])) :
                if str(type(dic['Resource directory'][i][j])) == '<class \'list\'>':
                    for k in range(len(dic['Resource directory'][i][j])) :
                        print(type(dic['Resource directory'][i][j][k]))
                        # print('[i({0})j({1})k({2})] >>> {3}\n'.format(i,j,k,dic['Resource directory'][i][j][k]['Structure']),end='')
                        print('[i({0})j({1})k({2})] >>> {3}\n'.format(i,j,k,dic['Resource directory'][i][j][k]),end='')
                        pp(dic['Resource directory'][i][j][k])
                        print('')
                else:
                    print(type(dic['Resource directory'][i][j]))
                    print('[i({0})j({1})] >>> {2}\n'.format(i,j,dic['Resource directory'][i][j]['Structure']),end='')
                    pp(dic['Resource directory'][i][j])
                    print('')
        else:
            print(type(dic['Resource directory'][i]))
            print('[i({0})] >>> {1}\n'.format(i,dic['Resource directory'][i]['Structure']),end='')
            pp(dic['Resource directory'][i])
            print('')
        ## input('')
    end_time = time.time()
    print('소요시간>>>',end_time-start_time)  


def pe_structure(failed_extract,good_or_bad,full_path,vir_file):
    if not os.path.exists(failed_extract):
        os.system('md \"{}\"'.format(failed_extract))
        
    # print('디렉토리 검색 중...')
    # print('파일갯수: {}'.format(number_of_files)+'\n-----------------------------\n')
    
    # for file_num in range(number_of_files):
    
    filename = full_path
    label = good_or_bad
    
    data_dict = {}
    # data_dict['ID'] = get_md5(filename)
    data_dict['Filename'] = filename
        
    # print('추출대상 >>>',filename)
    
    try:
        pe = pefile.PE(filename)
        dic = pe.dump_dict()
    except:
        os.system('copy \"{0}\" {1}'.format(filename,failed_extract))
        return 0
    
###################################################################################
    
    for i in range(0,len(__functions__)):
        try:
            data_dict.update(eval(__functions__[i]))
    ##eval(__functions__[5])
        except:
            print('error : can\'t print \'{}\' info'.format(__functions__[i]))

        # input('')
        # os.system('cls')
            
    # input(filename)
    # os.system('cls')
    data_dict['Label'] = label
    
###################################################################################

    data_frame = pd.DataFrame([data_dict],index=[vir_file])
    
    
    return data_frame


def printer(title, offsets, data_dict) :
    return
    
# def printer(title, offsets, data_dict) :
    # print(title)
    # for i,(key, value) in enumerate(data_dict.items()):
        # print(str(offsets[i]).ljust(20), key.ljust(55).rjust(40), value)

def dir_explorer(dir) : # 생성된 html파일 경로 list에 저장 함수
    dir_file_list = [],[],[]
    for path, dirs, files in os.walk(dir):
        for file in files:
            if path.split('\\')[-1].startswith('malware') == True :
                dir_file_list[0].append('1')
                dir_file_list[1].append(path+'\\'+file)
                dir_file_list[2].append(file)
            elif path.split('\\')[-1].startswith('goodware') == True :
                dir_file_list[0].append('0')
                dir_file_list[1].append(path+'\\'+file)
                dir_file_list[2].append(file)
            else:
                continue
    
    return dir_file_list


if __name__ == '__main__' :
    os.system('cls')
    
    dir = 'D:\\DATASET\\for_test\\분류완료[315099-1798(중복)=313301개]\\_대회_학습용_데이터셋_[10000개]\\[10000개]train_set' # 디렉토리 설정하면 해당 디렉토리 하위까지 탐색
    result_file = '..\\대회용데이터셋추출.csv'
    failed_extract = '..\\failed_extract'
    
    dir_file_list = dir_explorer(dir) # 디렉토리 내 모든 vir파일 탐색 후 list up
    
    for file_num in range(len(dir_file_list[1])):
        good_or_bad = dir_file_list[0][file_num] # 정상 혹은 악성 구분 라벨
        full_path = dir_file_list[1][file_num] # vir 파일의 절대경로
        vir_file = dir_file_list[2][file_num] # vir 파일의 이름

        data_frame = pe_structure(failed_extract,good_or_bad,full_path,vir_file)
        
        if str(type(data_frame)) == '<class \'pandas.core.frame.DataFrame\'>':   # pefile이 터지는 경우 data_frame은 0
            print('[{0} / {1}] 추출완료.\n'.format(file_num+1,len(dir_file_list[1])))
                
            if not os.path.exists(result_file):
                data_frame.to_csv(result_file, mode='w', index=False, encoding='utf-8-sig')
            else:
                data_frame.to_csv(result_file, mode='a', index=False, header=False, encoding='utf-8-sig')
        else:
            print('[{0} / {1}] 추출실패.\n'.format(file_num+1,len(dir_file_list[1])))
            continue


'''
    추후에 tls콜백 주소와 tls엔트리를 비교하는 피처를 필요시 제작할 것
'''