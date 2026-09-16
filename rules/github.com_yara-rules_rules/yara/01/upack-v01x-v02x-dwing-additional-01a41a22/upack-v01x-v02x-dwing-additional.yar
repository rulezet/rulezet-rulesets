import "pe"
rule Upack_V01X_V02X_Dwing_additional: PEiD
{
    strings:
        $a = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }
    condition:
        $a at pe.entry_point

}