import "pe"
rule EXEJoiner_v10: PEiD
{
    strings:
        $a = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }
    condition:
        $a at pe.entry_point

}