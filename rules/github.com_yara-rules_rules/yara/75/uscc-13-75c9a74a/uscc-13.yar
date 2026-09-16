import "pe"
rule USCC_13: PEiD
{
    strings:
        $a = { BB 00 00 B9 AF 00 30 0F 43 E2 FB 55 FE FE FD F9 FC FE FD F4 F6 FD E8 EF F9 4A A1 76 A5 5E C7 EE AC 05 C0 B2 69 6B C4 0E A1 6E 1E 50 E8 06 91 ED 4D 8C 96 87 C6 85 EE C3 9D 39 A4 7F DD 67 7C D8 66 79 9C 13 7A 35 92 17 14 B6 76 71 6E 30 EF AE }
    condition:
        $a at pe.entry_point

}