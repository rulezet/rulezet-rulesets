import "pe"
rule _Protector_v1111_DDeM_PE_Engine_v09_DDeM_CI_v092: PEiD
{
    strings:
        $a = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }
    condition:
        $a at pe.entry_point

}