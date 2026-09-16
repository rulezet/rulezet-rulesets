import "pe"
rule _PseudoSigner_01_Code_Lock_Anorganix: PEiD
{
    strings:
        $a = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9 }
    condition:
        $a at pe.entry_point

}