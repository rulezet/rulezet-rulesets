import "pe"
rule SuckStop_111: PEiD
{
    strings:
        $a = { 4B 41 4F 54 58 EB 02 8E 7C BE 10 00 B4 30 CD 21 EB 0A 9B 00 00 00 00 00 BF 00 00 B9 3C 03 77 02 CD 20 4E 75 E7 6A 00 0E 6A 69 FE C3 CF AC 66 64 33 06 0C 00 66 65 2B 06 90 06 8C EA 03 C2 CF 32 C7 AA CF 47 72 65 65 74 7A 20 74 6F 20 61 6C 6C }
    condition:
        $a at pe.entry_point

}