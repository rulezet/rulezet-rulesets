import "pe"
rule ASProtect_v12x: PEiD
{
    strings:
        $a = { 00 00 68 01 ?? ?? ?? C3 AA }
    condition:
        $a at pe.entry_point

}