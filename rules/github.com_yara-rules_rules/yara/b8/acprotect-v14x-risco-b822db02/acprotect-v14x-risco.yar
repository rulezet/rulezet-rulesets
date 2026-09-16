import "pe"
rule ACProtect_V14X_risco: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }
    condition:
        $a at pe.entry_point

}