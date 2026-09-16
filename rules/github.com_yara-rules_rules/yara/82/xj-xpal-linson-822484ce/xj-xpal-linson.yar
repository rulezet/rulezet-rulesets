import "pe"
rule XJ_XPAL_LiNSoN: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }
    condition:
        $a at pe.entry_point

}