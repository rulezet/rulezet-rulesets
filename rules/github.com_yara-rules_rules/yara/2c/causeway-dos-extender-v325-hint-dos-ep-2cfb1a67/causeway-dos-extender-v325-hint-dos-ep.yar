import "pe"
rule CauseWay_DOS_Extender_v325_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA 16 1F 26 ?? ?? ?? 83 ?? ?? 8E D0 FB 06 16 07 BE ?? ?? 8B FE B9 ?? ?? F3 A4 07 }
    condition:
        $a at pe.entry_point

}