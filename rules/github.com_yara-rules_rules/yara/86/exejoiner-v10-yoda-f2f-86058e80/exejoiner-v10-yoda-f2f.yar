import "pe"
rule ExeJoiner_V10_Yoda_f2f: PEiD
{
    strings:
        $a = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }
    condition:
        $a at pe.entry_point

}