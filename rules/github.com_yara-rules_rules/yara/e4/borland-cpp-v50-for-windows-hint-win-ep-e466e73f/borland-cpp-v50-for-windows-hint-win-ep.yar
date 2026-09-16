import "pe"
rule Borland_Cpp_v50_for_Windows_Hint_WIN_EP: PEiD
{
    strings:
        $a = { EB ?? 53 51 06 33 C0 50 9A ?? ?? ?? ?? 58 07 59 5B 9A }
    condition:
        $a at pe.entry_point

}