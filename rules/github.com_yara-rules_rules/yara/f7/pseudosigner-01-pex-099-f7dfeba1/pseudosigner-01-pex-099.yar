import "pe"
rule _PseudoSigner_01_PEX_099: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }
    condition:
        $a at pe.entry_point

}