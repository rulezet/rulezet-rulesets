import "pe"
rule ASProtect_10_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 90 5D 81 ED ?? ?? ?? 00 BB ?? ?? ?? 00 03 DD 2B 9D }
    condition:
        $a at pe.entry_point

}