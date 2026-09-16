import "pe"
rule unknown_by_GyikSoft_1: PEiD
{
    strings:
        $a = { 8C C9 81 C1 00 00 51 B9 00 00 51 00 00 00 00 00 00 06 00 00 00 00 00 83 EB 18 53 51 B8 00 00 8C CA 03 D0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 79 EE 00 00 00 00 00 00 BE 00 00 CB }
    condition:
        $a at pe.entry_point

}