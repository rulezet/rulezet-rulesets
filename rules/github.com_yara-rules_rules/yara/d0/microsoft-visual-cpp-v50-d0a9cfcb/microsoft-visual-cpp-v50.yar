import "pe"
rule Microsoft_Visual_Cpp_v50: PEiD
{
    strings:
        $a = { 24 ?? 8B 24 }
        $b = { 55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}