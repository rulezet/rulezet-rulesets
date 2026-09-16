import "pe"
rule SelfEnc_10: PEiD
{
    strings:
        $a = { BB 0F 01 B9 8F 18 33 C0 2E 80 2F 00 43 E2 F9 }
    condition:
        $a at pe.entry_point

}