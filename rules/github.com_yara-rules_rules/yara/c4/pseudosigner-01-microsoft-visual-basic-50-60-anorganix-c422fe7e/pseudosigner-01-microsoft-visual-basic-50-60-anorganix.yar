import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Basic_50_60_Anorganix: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }
    condition:
        $a at pe.entry_point

}