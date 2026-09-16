import "pe"
rule MinGW_GCC_v2x: PEiD
{
    strings:
        $a = { 55 89 E5 FF }
        $b = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}