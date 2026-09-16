import "pe"
rule Microsoft_QBasic_v30_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 8C C8 8E D8 E8 ?? ?? 8A 17 0A D2 74 ?? B4 ?? CD 21 43 }
    condition:
        $a at pe.entry_point

}