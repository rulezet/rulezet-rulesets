import "pe"
rule Borland_Delphi_vxx_Component: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 B4 B8 E8 E8 8D }
        $b = { C3 E9 ?? ?? ?? FF 8D 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}