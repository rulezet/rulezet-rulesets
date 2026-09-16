rule IcedIDPackerD
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "7b226f8cc05fa7d846c52eb0ec386ab37f9bae04372372509daa6bacc9f885d8"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 66 3B ED 74}
        $load = {41 B8 00 80 00 00 33 D2 48 8B 4C [2] EB ?? B9 69 04 00 00 E8 [4] 48 89 84 [2] 00 00 00 66 3B ED 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}