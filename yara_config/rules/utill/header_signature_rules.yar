rule DOS_HEADER_Signature{
    meta:
        info = "DOS HEADER 시그니쳐 체크"

    strings:
        $signature = "MZ"
    
    condition:
        $signature
}

rule NT_HEADER_Signature{
    meta:
        info = "NT HEADERS 시그니쳐 체크"
    
    strings:
        $signature = "PE"
    
    condition:
        $signature
}