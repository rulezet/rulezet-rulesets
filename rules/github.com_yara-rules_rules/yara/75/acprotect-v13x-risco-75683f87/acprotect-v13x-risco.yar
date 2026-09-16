import "pe"
rule ACProtect_V13X_risco: PEiD
{
    strings:
        $a = { 60 50 E8 01 00 00 00 75 83 }
    condition:
        $a at pe.entry_point

}