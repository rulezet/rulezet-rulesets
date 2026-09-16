import "pe"
rule unknown_by_JVP: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 06 33 C0 06 50 CB 81 BF 00 00 BE 00 00 E8 }
    condition:
        $a at pe.entry_point

}