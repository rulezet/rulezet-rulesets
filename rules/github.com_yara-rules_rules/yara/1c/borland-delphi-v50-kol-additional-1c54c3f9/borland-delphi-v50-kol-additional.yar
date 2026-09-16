import "pe"
rule Borland_Delphi_v50_KOL_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }
    condition:
        $a at pe.entry_point

}