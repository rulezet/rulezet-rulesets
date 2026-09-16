import "pe"
rule Petite_v14: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }
    condition:
        $a at pe.entry_point

}