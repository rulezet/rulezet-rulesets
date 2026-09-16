import "pe"
rule Vx_Phoenix927: PEiD
{
    strings:
        $a = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }
    condition:
        $a at pe.entry_point

}