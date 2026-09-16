import "pe"
rule Borland_Cpp_1991_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 2E 8C 06 ?? ?? 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F }
    condition:
        $a at pe.entry_point

}