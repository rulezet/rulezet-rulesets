import "pe"
rule MetaWare_High_C_Run_Time_Library_p_Phar_Lap_DOS_Extender_1983_89_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? 50 B8 ?? ?? 50 CB }
    condition:
        $a at pe.entry_point

}