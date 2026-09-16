import "pe"
rule _PseudoSigner_02_XCR_011_Anorganix: PEiD
{
    strings:
        $a = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }
    condition:
        $a at pe.entry_point

}