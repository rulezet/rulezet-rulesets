import "pe"
rule Themida_v2018_c2007_Oreans_Technologies: PEiD
{
    strings:
        $a = { 83 EC 04 50 53 E8 00 00 00 00 58 8B D8 2D 00 ?? ?? 00 2D ?? ?? ?? 00 05 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}