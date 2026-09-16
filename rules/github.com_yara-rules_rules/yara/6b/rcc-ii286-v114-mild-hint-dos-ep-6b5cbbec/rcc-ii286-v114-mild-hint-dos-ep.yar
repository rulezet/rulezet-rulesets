import "pe"
rule RCC_II286_v114_mild_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA BD ?? ?? BE ?? ?? 9C 46 30 ?? ?? ?? 99 }
    condition:
        $a at pe.entry_point

}