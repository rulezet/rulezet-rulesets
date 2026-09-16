import "pe"
rule EXELOCK_666_105: PEiD
{
    strings:
        $a = { BA 7E 08 BF 27 01 EB 01 EA E8 FB FE 48 79 7A 7F 2C 7E 2A 1C FA 48 78 F5 E3 AE 45 14 04 5A E9 F8 9E 89 18 96 01 5A B1 E0 08 E6 F2 8E FB 4A B1 9C 1D 9C 08 84 11 B1 F1 1F 1C F6 E5 22 CB 23 44 A0 CC 1B D9 BD D2 78 B6 B7 74 A6 E6 AF C4 71 62 AE }
    condition:
        $a at pe.entry_point

}