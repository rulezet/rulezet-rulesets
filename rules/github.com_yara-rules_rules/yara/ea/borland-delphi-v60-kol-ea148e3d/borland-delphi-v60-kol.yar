import "pe"
rule Borland_Delphi_v60_KOL: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 }
        $b = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}