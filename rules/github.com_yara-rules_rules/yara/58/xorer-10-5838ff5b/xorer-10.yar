import "pe"
rule XoReR_10: PEiD
{
    strings:
        $a = { BE 00 00 8B FE B9 6B 00 33 DB 80 C3 00 AC 32 C3 AA E2 F7 }
    condition:
        $a at pe.entry_point

}