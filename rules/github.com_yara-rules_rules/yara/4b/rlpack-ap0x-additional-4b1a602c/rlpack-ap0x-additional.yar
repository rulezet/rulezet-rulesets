import "pe"
rule RLPack_Ap0x_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A }
    condition:
        $a at pe.entry_point

}