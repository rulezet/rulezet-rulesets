import "pe"
rule UPX_093_UnHack32_12: PEiD
{
    strings:
        $a = { 60 BE 00 A0 43 00 8D BE 00 70 FC FF C7 87 D0 84 04 00 98 C1 DF 2D 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC }
    condition:
        $a at pe.entry_point

}