rule StealcV2DateCheck
{
    meta:
        author = "kevoreilly"
        description = "StealcV2 date check bypass"
        cape_options = "patch=$date32*-1:B000,patch=$date64*-2:B00090"
    strings:
        $date32 = {F3 A5 8D 45 ?? 50 E8 [4] 59 8B F8 8B F2 8D 45 ?? 50 E8 [4] 59 3B F2 7C 08 7F 04 3B F8 76 02 B3 01 8A C3}
        $date64 = {0F 11 44 [2] 0F 11 8C [2] 00 00 00 89 8C [2] 00 00 00 48 8D 4C [2] E8 [4] 48 8B D8 48 8D 4C [2] E8 [4] 48 3B D8 0F 9F C0}
    condition:
        uint16(0) == 0x5A4D and any of them
}