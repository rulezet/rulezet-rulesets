import "pe"
rule Vx_Caterpillar1575_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 06 1E 8C C0 0E 1F 0E 07 A3 ?? ?? 8C D0 A3 ?? ?? B0 ?? E6 20 FC ?? C0 8E D8 ?? F6 BF ?? ?? B9 ?? ?? F2 A4 1E 17 }
    condition:
        $a at pe.entry_point

}