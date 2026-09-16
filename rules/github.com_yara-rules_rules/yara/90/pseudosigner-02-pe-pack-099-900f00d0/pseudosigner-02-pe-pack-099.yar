import "pe"
rule _PseudoSigner_02_PE_Pack_099: PEiD
{
    strings:
        $a = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }
    condition:
        $a at pe.entry_point

}