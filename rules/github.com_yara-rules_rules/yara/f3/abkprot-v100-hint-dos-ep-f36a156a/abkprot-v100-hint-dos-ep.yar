import "pe"
rule ABKprot_v100_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? 9C 8C C0 06 5B 59 51 53 BA ?? ?? 87 F2 56 CF 0E 1F 0E 07 }
    condition:
        $a at pe.entry_point

}