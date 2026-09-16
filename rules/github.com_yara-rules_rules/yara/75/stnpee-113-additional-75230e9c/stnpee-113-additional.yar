import "pe"
rule STNPEE_113_additional: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 }
    condition:
        $a at pe.entry_point

}