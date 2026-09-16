rule IcedSleep
{
    meta:
        author = "kevoreilly"
        description = "IcedID sleep bypass"
        cape_options = "force-sleepskip=1"
        packed = "e99f3517a36a9f7a55335699cfb4d84d08b042d47146119156f7f3bab580b4d7"
    strings:
        $sleep = {89 4C 24 08 48 83 EC 38 8B 44 24 40 48 69 C0 10 27 00 00 48 F7 D8 48 89 44 24 20 48 8D 54 24 20 33 C9 FF 15 [4] 48 83 C4 38 C3}
    condition:
        uint16(0) == 0x5A4D and all of them
}