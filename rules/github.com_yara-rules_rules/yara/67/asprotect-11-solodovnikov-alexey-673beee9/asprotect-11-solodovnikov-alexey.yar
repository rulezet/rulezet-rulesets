import "pe"
rule ASProtect_11_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 ?? 04 00 00 E9 ?? ?? ?? ?? ?? ?? ?? EE }
    condition:
        $a at pe.entry_point

}