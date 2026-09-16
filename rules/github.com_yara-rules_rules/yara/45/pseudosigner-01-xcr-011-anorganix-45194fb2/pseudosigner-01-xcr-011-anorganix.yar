import "pe"
rule PseudoSigner_01_XCR_011_Anorganix: PEiD
{
    strings:
        $a = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }
    condition:
        $a at pe.entry_point

}