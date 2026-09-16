import "pe"
rule SuckStop_108: PEiD
{
    strings:
        $a = { 4B 41 4F 54 5C EB 02 8E 7C BE 10 00 B4 30 CD 21 EB 0A 9B 00 00 00 00 00 BF 00 00 B9 3C 03 77 02 CD 20 4E 75 E7 6A 00 0E 6A 67 FE C3 CF AC 66 64 33 06 0C 00 66 65 2B 06 90 06 8C EA 03 C2 CF 32 C7 AA CF 57 69 6E 64 6F 77 73 20 73 75 78 78 21 }
    condition:
        $a at pe.entry_point

}