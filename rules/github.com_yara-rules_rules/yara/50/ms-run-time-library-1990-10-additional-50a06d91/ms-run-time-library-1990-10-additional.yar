import "pe"
rule MS_Run_Time_Library_1990_10_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB }
    condition:
        $a at pe.entry_point

}