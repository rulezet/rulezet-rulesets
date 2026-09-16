import "pe"
rule ASProtect_123_RC4_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 F0 58 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}