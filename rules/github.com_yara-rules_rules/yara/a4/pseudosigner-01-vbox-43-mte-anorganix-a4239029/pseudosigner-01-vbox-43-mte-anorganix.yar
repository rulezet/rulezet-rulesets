import "pe"
rule PseudoSigner_01_VBOX_43_MTE_Anorganix: PEiD
{
    strings:
        $a = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9 }
    condition:
        $a at pe.entry_point

}