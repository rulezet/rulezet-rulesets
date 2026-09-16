import "pe"
rule Borland_Cpp_for_Win32_1999: PEiD
{
    strings:
        $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B }
        $b = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}