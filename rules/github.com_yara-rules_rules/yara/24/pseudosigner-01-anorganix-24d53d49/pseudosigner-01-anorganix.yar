import "pe"
rule _PseudoSigner_01_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }
    condition:
        $a at pe.entry_point

}