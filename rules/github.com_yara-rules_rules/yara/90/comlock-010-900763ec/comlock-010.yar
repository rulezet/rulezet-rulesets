import "pe"
rule ComLock_010: PEiD
{
    strings:
        $a = { EB 0E 90 00 00 00 00 2D 43 4F 4D 4C 4F 43 4B 2D BB 00 00 BE 04 00 81 C6 03 01 03 F3 BF 00 01 B9 03 00 F3 A4 2E 8A 87 06 01 BE 03 01 8B CB 2E 30 04 46 FE C0 E2 F8 33 C0 33 DB 33 C9 33 D2 33 FF 33 F6 33 ED 0E 50 55 8B EC C7 46 02 00 01 5D CB }
    condition:
        $a at pe.entry_point

}