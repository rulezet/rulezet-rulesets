import "pe"
rule _PseudoSigner_02_VBOX_43_MTE_Anorganix: PEiD
{
    strings:
        $a = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }
    condition:
        $a at pe.entry_point

}