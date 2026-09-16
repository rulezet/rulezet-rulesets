import "pe"
rule Borland_Delphi: PEiD
{
    strings:
        $a = { C3 E9 FF 8D }
        $b = { 55 8B EC 83 C4 F4 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}