import "pe"
rule Microsoft_Visual_Cpp_vxx: PEiD
{
    strings:
        $a = { 53 55 56 8B 85 F6 57 B8 75 8B 85 C9 75 33 C0 5F 5E 5D 5B }
        $b = { 53 55 56 8B ?? ?? ?? 85 F6 57 B8 ?? ?? ?? ?? 75 ?? 8B ?? ?? ?? ?? ?? 85 C9 75 ?? 33 C0 5F 5E 5D 5B C2 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}