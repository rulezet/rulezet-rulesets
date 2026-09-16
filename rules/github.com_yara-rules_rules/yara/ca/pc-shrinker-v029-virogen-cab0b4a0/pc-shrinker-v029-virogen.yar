import "pe"
rule PC_Shrinker_v029_Virogen: PEiD
{
    strings:
        $a = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 00 8D B5 35 39 40 }
    condition:
        $a at pe.entry_point

}