import "pe"
rule Borland_Delphi_Setup_Module: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 }
        $b = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}