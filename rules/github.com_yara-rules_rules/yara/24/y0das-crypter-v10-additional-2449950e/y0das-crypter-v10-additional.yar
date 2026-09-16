import "pe"
rule y0das_Crypter_v10_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }
    condition:
        $a at pe.entry_point

}