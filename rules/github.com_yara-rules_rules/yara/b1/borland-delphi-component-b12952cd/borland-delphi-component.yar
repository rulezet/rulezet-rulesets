import "pe"
rule Borland_Delphi_Component: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 04 83 }
        $b = { C3 E9 ?? ?? ?? FF 8D 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}