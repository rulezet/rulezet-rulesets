import "pe"
rule DotFix_NiceProtect_vna_additional: PEiD
{
    strings:
        $a = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }
    condition:
        $a at pe.entry_point

}