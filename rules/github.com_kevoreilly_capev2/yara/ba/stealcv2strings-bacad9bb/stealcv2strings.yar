rule StealcV2Strings
{
    meta:
        author = "kevoreilly"
        description = "StealcV2 string decryption"
        cape_options = "bp0=$decode32*,action0=string:[esp],bp1=$decode64,action1=string:eax,bp2=$dump,action2=dumpstrings,count=0,typestring=Stealc Strings"
        packed = "2f42dcf05dd87e6352491ff9d4ea3dc3f854df53d548a8da0c323be42df797b6"
        packed = "8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387"
    strings:
        $decode32 = {AB AB AB AB 8B 45 0C 89 4E 10 89 4E 14 39 45 08 75 0B C7 46 14 0F 00 00 00 88 0E EB 0F 2B 45 08 50 51 FF 75 ?? 8B}
        $decode64 = {40 53 48 83 EC 20 48 8B 19 48 85 DB 74 ?? 48 8B 53 18 48 83 FA 0F 76 2C 48 8B 0B 48 FF C2 48 81 FA 00 10 00 00 72}
        $dump32 = {33 C0 89 46 30 88 46 34 89 46 38 89 46 3C 89 46 40 89 46 44 89 46 48 89 46 4C 89 46 50 89 46 54 89 46 58 8B C6 5F 5E C3}
        $dump64 = {48 8B C7 89 6F 40 40 88 6F 44 48 89 6F 48 48 89 6F 50 48 89 6F 58 48 89 6F 60 48 89 6F 68 48 89 6F 70 48 89 6F 78 48 89}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}