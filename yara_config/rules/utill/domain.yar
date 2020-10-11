rule domain {
    meta:
        info = "Domain Strongs"
    
    strings:
        $domain_regex = /([\w\.-]+)/ wide ascii
    
    condition:
        $domain_regex
}
