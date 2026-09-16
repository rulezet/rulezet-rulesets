import "pe"
rule HEALTH_v51_by_Muslim_MPolyak_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E E8 ?? ?? 2E 8C 06 ?? ?? 2E 89 3E ?? ?? 8B D7 B8 ?? ?? CD 21 8B D8 0E 1F E8 ?? ?? 06 57 A1 ?? ?? 26 }
    condition:
        $a at pe.entry_point

}