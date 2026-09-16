import "pe"
rule Exe_Shield_v27b_additional: PEiD
{
    strings:
        $a = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
    condition:
        $a at pe.entry_point

}