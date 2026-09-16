import "pe"
rule _PseudoSigner_01_PE_Protect_09_Anorganix: PEiD
{
    strings:
        $a = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }
    condition:
        $a at pe.entry_point

}