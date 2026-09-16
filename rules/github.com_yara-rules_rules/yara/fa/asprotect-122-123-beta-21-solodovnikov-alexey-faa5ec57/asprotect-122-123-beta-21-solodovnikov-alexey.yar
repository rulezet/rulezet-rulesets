import "pe"
rule ASProtect_122_123_Beta_21_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 E0 46 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}