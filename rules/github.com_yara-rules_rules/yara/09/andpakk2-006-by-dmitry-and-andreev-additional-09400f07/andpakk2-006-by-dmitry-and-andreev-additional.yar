import "pe"
rule ANDpakk2_006_by_Dmitry_AND_Andreev_additional: PEiD
{
    strings:
        $a = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 }
    condition:
        $a at pe.entry_point

}