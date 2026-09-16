import "pe"
rule SCRAMB_v120_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? E8 ?? ?? 5B 0E 1F 81 ?? ?? ?? 8B C3 05 ?? ?? 50 8B C8 03 D1 2B FA C3 }
    condition:
        $a at pe.entry_point

}