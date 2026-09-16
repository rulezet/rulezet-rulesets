import "pe"
rule Symantec_C_v400_p_Libraries_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA B8 ?? ?? DB E3 8E D8 8C 06 ?? ?? 8B D8 2B 1E ?? ?? 89 1E ?? ?? 26 }
    condition:
        $a at pe.entry_point

}