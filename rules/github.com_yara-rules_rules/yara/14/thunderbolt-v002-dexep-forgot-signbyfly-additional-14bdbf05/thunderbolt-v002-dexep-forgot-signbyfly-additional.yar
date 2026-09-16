import "pe"
rule Thunderbolt_V002_deXep_forgot_SignByfly_additional: PEiD
{
    strings:
        $a = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 }
    condition:
        $a at pe.entry_point

}