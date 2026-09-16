import "pe"
rule MCLOCK_13: PEiD
{
    strings:
        $a = { 90 90 90 FA 29 C0 8E C0 26 C6 06 04 00 00 26 C6 06 05 00 00 26 8C 0E 06 00 26 C6 06 0C 00 00 26 C6 06 0D 00 00 26 8C 0E 0E 00 FB CD 01 8C C8 8E C0 CD 03 29 C0 BC 00 00 50 E9 00 00 BE 00 00 B3 00 B9 21 00 2E 30 1C 46 E2 FA CF }
    condition:
        $a at pe.entry_point

}