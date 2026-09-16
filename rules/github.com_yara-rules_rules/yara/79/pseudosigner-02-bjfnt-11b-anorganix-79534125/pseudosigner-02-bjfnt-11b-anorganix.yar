import "pe"
rule _PseudoSigner_02_BJFNT_11b_Anorganix: PEiD
{
    strings:
        $a = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }
    condition:
        $a at pe.entry_point

}