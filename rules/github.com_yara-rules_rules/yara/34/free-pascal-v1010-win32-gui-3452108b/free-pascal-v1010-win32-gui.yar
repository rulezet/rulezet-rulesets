import "pe"
rule Free_Pascal_v1010_win32_GUI: PEiD
{
    strings:
        $a = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }
    condition:
        $a at pe.entry_point

}