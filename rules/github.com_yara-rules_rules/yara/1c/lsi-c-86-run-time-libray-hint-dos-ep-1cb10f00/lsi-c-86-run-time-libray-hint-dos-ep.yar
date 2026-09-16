import "pe"
rule LSI_C_86_Run_Time_Libray_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B8 ?? ?? 8E C0 06 17 BC ?? ?? 26 8C ?? ?? ?? B4 30 CD 21 26 A3 ?? ?? FC }
    condition:
        $a at pe.entry_point

}