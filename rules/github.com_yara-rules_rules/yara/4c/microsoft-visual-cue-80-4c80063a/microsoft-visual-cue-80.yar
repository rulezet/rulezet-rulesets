import "pe"
rule Microsoft_Visual_Cue_80: PEiD
{
    strings:
        $a = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B }
    condition:
        $a at pe.entry_point

}