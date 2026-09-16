import "pe"
rule PC_Shrinker_v020_Virogen: PEiD
{
    strings:
        $a = { E8 E8 01 00 00 60 01 AD B3 27 40 00 68 }
    condition:
        $a at pe.entry_point

}