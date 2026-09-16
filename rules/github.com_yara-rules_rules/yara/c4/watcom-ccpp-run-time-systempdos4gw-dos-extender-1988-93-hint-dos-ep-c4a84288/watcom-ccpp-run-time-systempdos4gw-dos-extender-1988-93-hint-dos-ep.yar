import "pe"
rule WATCOM_CCpp_Run_Time_systempDOS4GW_DOS_Extender_1988_93_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BF ?? ?? 8E D7 81 C4 ?? ?? BE ?? ?? 2B F7 8B C6 B1 ?? D3 }
    condition:
        $a at pe.entry_point

}