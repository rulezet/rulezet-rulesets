rule PEiD_01089_Microsoft_Visual_C___8_0_
{
    meta:
        description = "[Microsoft Visual C++ 8.0]"
        ep_only = "true"
    strings:
        $a = {48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 ?? ?? FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC}
    condition:
        $a
}