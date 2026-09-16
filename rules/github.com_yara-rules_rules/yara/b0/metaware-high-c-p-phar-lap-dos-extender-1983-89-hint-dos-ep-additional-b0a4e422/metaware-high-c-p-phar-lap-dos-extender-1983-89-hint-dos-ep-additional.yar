import "pe"
rule MetaWare_High_C_p_Phar_Lap_DOS_Extender_1983_89_Hint_DOS_EP_additional: PEiD
{
    strings:
        $a = { EB ?? 33 ED 2E 8E 1E ?? ?? 26 A1 ?? ?? A3 ?? ?? 26 8B 1E ?? ?? B1 ?? 4B }
    condition:
        $a at pe.entry_point

}