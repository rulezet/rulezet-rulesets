import "pe"
rule _v10_additional: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C 30 40 00 }
    condition:
        $a at pe.entry_point

}