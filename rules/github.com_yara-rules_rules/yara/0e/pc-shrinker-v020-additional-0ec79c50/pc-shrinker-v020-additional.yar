import "pe"
rule PC_Shrinker_v020_additional: PEiD
{
    strings:
        $a = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
    condition:
        $a at pe.entry_point

}