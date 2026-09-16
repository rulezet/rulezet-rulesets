import "pe"
rule SimplePack_V1X_Method2_bagie: PEiD
{
    strings:
        $a = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 }
    condition:
        $a at pe.entry_point

}