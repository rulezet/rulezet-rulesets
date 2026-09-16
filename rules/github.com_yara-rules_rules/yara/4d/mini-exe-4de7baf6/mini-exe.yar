import "pe"
rule MINI_EXE: PEiD
{
    strings:
        $a = { B8 00 00 BA 00 00 05 00 00 3B 06 02 00 73 1C 2D 20 00 FA 8E D0 FB 2D 00 00 90 8E C0 50 B9 00 00 90 33 FF 57 BE 46 01 FC F3 A5 CB B4 09 BA 34 01 CD 21 CD 20 4D 65 6D 6F 72 79 20 6E 6F 74 20 65 6E 6F 75 67 68 24 8C DB 53 83 C3 00 90 03 DA 8C }
    condition:
        $a at pe.entry_point

}