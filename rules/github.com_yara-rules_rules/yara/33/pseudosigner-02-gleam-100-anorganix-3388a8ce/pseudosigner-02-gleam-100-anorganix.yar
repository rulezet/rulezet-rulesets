import "pe"
rule _PseudoSigner_02_Gleam_100_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }
    condition:
        $a at pe.entry_point

}