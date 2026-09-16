import "pe"
rule Borland_Cpp_1992_1994_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8C C8 8E D8 8C 1E ?? ?? 8C 06 ?? ?? 8C 06 ?? ?? 8C 06 }
    condition:
        $a at pe.entry_point

}