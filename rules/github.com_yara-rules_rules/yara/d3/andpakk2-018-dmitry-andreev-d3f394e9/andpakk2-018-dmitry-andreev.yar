import "pe"
rule ANDpakk2_018_Dmitry_Andreev: PEiD
{
    strings:
        $a = { FC BE D4 00 40 00 BF 00 ?? ?? 00 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8? }
    condition:
        $a at pe.entry_point

}