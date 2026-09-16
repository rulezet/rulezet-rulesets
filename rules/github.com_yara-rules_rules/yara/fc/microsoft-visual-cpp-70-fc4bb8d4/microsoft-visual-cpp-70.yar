import "pe"
rule Microsoft_Visual_Cpp_70: PEiD
{
    strings:
        $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83 }
        $b = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 8B 75 0C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}