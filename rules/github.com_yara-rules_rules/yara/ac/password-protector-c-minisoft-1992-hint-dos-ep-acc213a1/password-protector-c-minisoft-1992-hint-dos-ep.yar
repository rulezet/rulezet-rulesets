import "pe"
rule Password_Protector_c_MiniSoft_1992_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }
    condition:
        $a at pe.entry_point

}