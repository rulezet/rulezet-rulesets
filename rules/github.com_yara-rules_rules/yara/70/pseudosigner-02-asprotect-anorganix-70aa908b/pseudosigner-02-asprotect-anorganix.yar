import "pe"
rule _PseudoSigner_02_ASProtect_Anorganix: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
    condition:
        $a at pe.entry_point

}