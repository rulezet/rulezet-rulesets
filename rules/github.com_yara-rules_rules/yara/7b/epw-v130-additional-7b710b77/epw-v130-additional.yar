import "pe"
rule EPW_v130_additional: PEiD
{
    strings:
        $a = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }
    condition:
        $a at pe.entry_point

}