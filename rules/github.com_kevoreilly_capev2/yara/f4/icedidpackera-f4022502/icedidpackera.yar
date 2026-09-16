rule IcedIDPackerA
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "fbad60002286599ca06d0ecb3624740efbf13ee5fda545341b3e0bf4d5348cfe"
    strings:
        $init = "init"
        $export = {48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 81 EC [2] 00 00 41 8B E9 49 8B F0 48 8B FA 48 8B D9}
        $alloc = {8B 50 50 33 C9 44 8D 49 40 41 B8 00 30 00 00 FF 15 [4] 48 89 44 24 28 [0-3] 48 89 84 24 ?? 00 00 00 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}