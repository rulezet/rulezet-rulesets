import "pe"
rule Borland_Cpp_DLL: PEiD
{
    strings:
        $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }
        $b = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}