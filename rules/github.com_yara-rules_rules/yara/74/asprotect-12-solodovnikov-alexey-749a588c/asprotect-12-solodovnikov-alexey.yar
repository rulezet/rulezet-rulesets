import "pe"
rule ASProtect_12_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? C3 }
    condition:
        $a at pe.entry_point

}