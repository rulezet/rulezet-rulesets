import "pe"
rule CodeSafe_30: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 5C 53 56 57 E8 00 00 00 00 8B 04 24 5A 83 E8 0E 8B D8 89 5D F8 2D 00 00 00 01 89 45 E0 8B C8 81 C1 70 00 00 01 89 19 8B D8 81 C3 E0 00 00 01 89 5D F4 8B 0B 0B C9 74 06 5F 5E 5B C9 FF E1 8B D0 81 C2 6C 00 00 01 8B 0A 8B D0 81 }
    condition:
        $a at pe.entry_point

}