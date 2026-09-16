import "pe"
rule Microsoft_Visual_Cpp_DLL: PEiD
{
    strings:
        $a = { 53 56 57 BB 01 8B 24 }
        $b = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}