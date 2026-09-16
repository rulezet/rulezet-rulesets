import "pe"
rule nbuild_v10_soft_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2 }
    condition:
        $a at pe.entry_point

}