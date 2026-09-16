import "pe"
rule ASProtect_20: PEiD
{
    strings:
        $a = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}