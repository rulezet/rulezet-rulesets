import "pe"
rule MetaWare_High_C_p_Phar_Lap_DOS_Extender_1983_89: PEiD
{
    strings:
        $a = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }
    condition:
        $a at pe.entry_point

}