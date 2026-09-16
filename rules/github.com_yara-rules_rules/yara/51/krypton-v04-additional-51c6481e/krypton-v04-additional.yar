import "pe"
rule Krypton_v04_additional: PEiD
{
    strings:
        $a = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }
    condition:
        $a at pe.entry_point

}