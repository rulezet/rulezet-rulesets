import "pe"
rule EXE2COM_200: PEiD
{
    strings:
        $a = { E8 00 00 5B 81 EB 1D 00 8D B7 00 00 BF 00 01 B9 07 00 F3 A5 8D B7 FC 00 53 8C CF 83 C7 10 AD 09 C0 74 63 91 AD 01 F8 8E C0 AD 93 26 01 3F E2 F9 EB EC 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 31 2D 31 39 39 35 20 62 79 20 50 53 50 }
    condition:
        $a at pe.entry_point

}