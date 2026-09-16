import "pe"
rule _PseudoSigner_01_ASProtect_Anorganix_additional: PEiD
{
    strings:
        $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }
    condition:
        $a at pe.entry_point

}