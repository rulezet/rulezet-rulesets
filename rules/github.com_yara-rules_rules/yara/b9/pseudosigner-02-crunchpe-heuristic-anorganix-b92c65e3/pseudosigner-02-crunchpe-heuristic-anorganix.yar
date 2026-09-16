import "pe"
rule PseudoSigner_02_CrunchPE_Heuristic_Anorganix: PEiD
{
    strings:
        $a = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 }
    condition:
        $a at pe.entry_point

}