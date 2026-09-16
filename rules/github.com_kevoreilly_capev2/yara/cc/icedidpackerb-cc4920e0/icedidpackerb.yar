rule IcedIDPackerB
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "6517ef2c579002ec62ddeb01a3175917c75d79ceca355c415a4462922c715cb6"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 4C 24 08 41 55 41 56 41 57 48 81 EC ?? 00 00 00 B9 [2] 00 00 4C 8B EA E8}
        $loop = {8B C2 48 8D 49 01 83 E0 07 FF C2 0F B6 44 30 ?? 30 41 FF 3B D5 72}
            condition:
        uint16(0) == 0x5A4D and all of them
}