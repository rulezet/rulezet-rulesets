import "pe"
rule PECrc32_V088_ZhouJinYu: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }
    condition:
        $a at pe.entry_point

}