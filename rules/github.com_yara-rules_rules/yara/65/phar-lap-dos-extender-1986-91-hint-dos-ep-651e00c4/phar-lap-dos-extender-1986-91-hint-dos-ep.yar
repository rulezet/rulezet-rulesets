import "pe"
rule Phar_Lap_DOS_Extender_1986_91_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 8C D8 8E C0 B8 ?? ?? 8E D8 BB ?? ?? 8C C0 2B D8 81 ?? ?? ?? B4 4A CD 21 }
    condition:
        $a at pe.entry_point

}