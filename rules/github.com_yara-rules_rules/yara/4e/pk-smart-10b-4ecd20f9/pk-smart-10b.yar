import "pe"
rule PK_Smart_10b: PEiD
{
    strings:
        $a = { BA 00 00 8C C8 8B C8 03 C2 81 C1 00 00 51 B9 00 00 51 1E 8C D3 8D 6F 00 55 B1 00 51 FC 4B BE 3C 00 33 FF 8E D8 8E C3 B1 08 F3 A5 48 4A 79 EE 0E 07 8E DB 33 F6 33 FF CB }
    condition:
        $a at pe.entry_point

}