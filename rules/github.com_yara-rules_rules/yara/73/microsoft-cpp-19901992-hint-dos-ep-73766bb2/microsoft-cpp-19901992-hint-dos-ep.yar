import "pe"
rule Microsoft_Cpp_19901992_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB }
    condition:
        $a at pe.entry_point

}