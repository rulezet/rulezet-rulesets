import "pe"
rule PseudoSigner_02_Microsoft_Visual_Basic_50_60: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }
    condition:
        $a at pe.entry_point

}