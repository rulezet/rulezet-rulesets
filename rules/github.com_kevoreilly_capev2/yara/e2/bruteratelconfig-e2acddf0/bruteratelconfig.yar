rule BruteRatelConfig
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Config Extraction"
        cape_options = "clear,br1=$decode,count=0,action0=string:eax,typestring=BruteRatel Config"
    strings:
        $decode = {55 57 56 53 48 83 EC ?? 31 C0 48 89 CB 48 89 D7 44 89 C6 44 89 CD 44 39 01 77 ?? 41 8D 48 01 E8 [4] 31 C9}
    condition:
        all of them
}