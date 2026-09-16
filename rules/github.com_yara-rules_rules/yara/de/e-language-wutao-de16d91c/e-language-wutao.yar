import "pe"
rule E_Language_WuTao: PEiD
{
    strings:
        $a = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }
    condition:
        $a at pe.entry_point

}