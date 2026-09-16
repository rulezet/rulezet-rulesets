import "pe"
rule RLPack_V118_Basic_Edition_aPlib_043_ap0x: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 }
    condition:
        $a at pe.entry_point

}