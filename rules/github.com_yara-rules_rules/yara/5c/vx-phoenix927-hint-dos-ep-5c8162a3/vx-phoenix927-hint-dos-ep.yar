import "pe"
rule Vx_Phoenix927_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }
    condition:
        $a at pe.entry_point

}