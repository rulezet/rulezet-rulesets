import "pe"
rule PESpin_0b_01_CyberBob: PEiD
{
    strings:
        $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 }
    condition:
        $a at pe.entry_point

}