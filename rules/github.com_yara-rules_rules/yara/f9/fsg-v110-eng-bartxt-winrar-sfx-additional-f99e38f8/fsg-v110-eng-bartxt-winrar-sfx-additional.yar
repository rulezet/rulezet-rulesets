import "pe"
rule FSG_v110_Eng_bartxt_WinRAR_SFX_additional: PEiD
{
    strings:
        $a = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }
    condition:
        $a at pe.entry_point

}