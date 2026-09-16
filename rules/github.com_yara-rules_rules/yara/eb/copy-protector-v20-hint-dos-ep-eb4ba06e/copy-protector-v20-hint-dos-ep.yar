import "pe"
rule Copy_Protector_v20_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F }
    condition:
        $a at pe.entry_point

}