import "pe"
rule RCC_II286_v114_hard_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA BD ?? ?? B2 ?? 50 3F F2 }
    condition:
        $a at pe.entry_point

}