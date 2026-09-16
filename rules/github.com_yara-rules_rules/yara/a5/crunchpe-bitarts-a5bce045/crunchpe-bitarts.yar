import "pe"
rule CrunchPE_BitArts: PEiD
{
    strings:
        $a = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 }
    condition:
        $a at pe.entry_point

}