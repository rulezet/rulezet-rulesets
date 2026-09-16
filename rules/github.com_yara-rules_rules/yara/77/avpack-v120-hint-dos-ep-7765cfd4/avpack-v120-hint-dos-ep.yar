import "pe"
rule AVPACK_v120_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB }
    condition:
        $a at pe.entry_point

}