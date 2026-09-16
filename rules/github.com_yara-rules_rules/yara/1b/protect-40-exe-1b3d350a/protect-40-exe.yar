import "pe"
rule Protect_40_EXE: PEiD
{
    strings:
        $a = { 8C DB 0E 0E 1F 07 B9 00 00 E8 00 00 5E 81 C6 11 00 89 F7 AC 34 00 AA E2 FA 8E DB 8E C3 }
    condition:
        $a at pe.entry_point

}