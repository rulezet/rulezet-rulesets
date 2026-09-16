import "pe"
rule MS_Run_Time_Library_1990_10_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB }
    condition:
        $a at pe.entry_point

}