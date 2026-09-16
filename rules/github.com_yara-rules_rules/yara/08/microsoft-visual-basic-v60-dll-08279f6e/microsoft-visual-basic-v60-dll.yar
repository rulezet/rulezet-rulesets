import "pe"
rule Microsoft_Visual_Basic_v60_DLL: PEiD
{
    strings:
        $a = { 55 89 E5 E8 C9 C3 45 58 }
        $b = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}