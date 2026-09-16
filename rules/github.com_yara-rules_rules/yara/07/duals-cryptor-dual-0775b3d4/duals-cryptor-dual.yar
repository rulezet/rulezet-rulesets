import "pe"
rule Duals_Cryptor_dual: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E }
    condition:
        $a at pe.entry_point

}