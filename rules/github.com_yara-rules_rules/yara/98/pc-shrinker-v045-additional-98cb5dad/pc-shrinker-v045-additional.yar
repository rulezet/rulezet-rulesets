import "pe"
rule PC_Shrinker_v045_additional: PEiD
{
    strings:
        $a = { BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
    condition:
        $a at pe.entry_point

}