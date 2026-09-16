import "pe"
rule Free_Pascal_09910: PEiD
{
    strings:
        $a = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }
    condition:
        $a at pe.entry_point

}