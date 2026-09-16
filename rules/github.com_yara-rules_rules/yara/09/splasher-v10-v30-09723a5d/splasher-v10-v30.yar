import "pe"
rule Splasher_v10_v30: PEiD
{
    strings:
        $a = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }
    condition:
        $a at pe.entry_point

}