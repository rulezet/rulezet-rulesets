import "pe"
rule ReversingLabsProtector_074_beta_Ap0x: PEiD
{
    strings:
        $a = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}