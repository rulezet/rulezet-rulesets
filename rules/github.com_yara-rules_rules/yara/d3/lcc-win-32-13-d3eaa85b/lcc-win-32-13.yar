import "pe"
rule Lcc_win_32_13: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 00 00 00 00 68 9A 10 40 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 }
    condition:
        $a at pe.entry_point

}