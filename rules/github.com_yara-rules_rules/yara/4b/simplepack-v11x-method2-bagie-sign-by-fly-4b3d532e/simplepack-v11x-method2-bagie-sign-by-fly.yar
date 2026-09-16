import "pe"
rule SimplePack_V11X_Method2_bagie_Sign_by_fly: PEiD
{
    strings:
        $a = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 }
    condition:
        $a at pe.entry_point

}