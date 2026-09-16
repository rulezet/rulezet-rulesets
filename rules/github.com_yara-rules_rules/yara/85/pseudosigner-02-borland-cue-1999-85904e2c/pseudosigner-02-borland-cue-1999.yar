import "pe"
rule PseudoSigner_02_Borland_Cue_1999: PEiD
{
    strings:
        $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }
    condition:
        $a at pe.entry_point

}