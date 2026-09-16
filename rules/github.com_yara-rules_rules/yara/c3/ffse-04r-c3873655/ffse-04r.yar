import "pe"
rule FFSE_04R: PEiD
{
    strings:
        $a = { 60 E9 B2 00 EB 01 C7 E8 6C 00 FC 0F 21 D1 FA 68 00 00 07 06 1F FF E1 52 91 A7 B5 D8 6A 50 A8 67 76 6E 30 86 D8 87 91 A7 40 88 92 71 25 EB 03 EB FC 83 66 C1 CC 10 EB 01 F7 E8 3A 00 B9 EB 03 EB FC C6 B9 00 08 33 F6 BF EB 03 EB FC C0 8B FE 8B }
    condition:
        $a at pe.entry_point

}