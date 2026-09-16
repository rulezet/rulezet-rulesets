import "pe"
rule FSG_v110_Eng_bartxt_WinRAR_SFX: PEiD
{
    strings:
        $a = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
    condition:
        $a at pe.entry_point

}