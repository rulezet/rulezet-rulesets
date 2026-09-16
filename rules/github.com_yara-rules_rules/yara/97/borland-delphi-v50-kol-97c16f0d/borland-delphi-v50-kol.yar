import "pe"
rule Borland_Delphi_v50_KOL: PEiD
{
    strings:
        $a = { 53 8B D8 33 C0 A3 6A ?? E8 FF A3 A1 A3 33 C0 A3 33 C0 A3 }
        $b = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}