import "pe"
rule RCC_II286_v102_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA BD ?? ?? 93 C8 ?? ?? ?? 54 62 E9 }
    condition:
        $a at pe.entry_point

}