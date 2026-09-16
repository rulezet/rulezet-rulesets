import "pe"
rule PEBundle_012_Jeremy_Collake: PEiD
{
    strings:
        $a = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 7F 23 40 00 0B C0 0F 84 D5 01 00 00 89 85 05 23 40 00 83 BD C3 22 40 00 01 74 0D 83 BD BF 22 40 00 01 74 2A }
    condition:
        $a at pe.entry_point

}