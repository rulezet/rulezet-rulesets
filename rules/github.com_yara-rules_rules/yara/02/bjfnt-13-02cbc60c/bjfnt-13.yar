import "pe"
rule BJFNT_13: PEiD
{
    strings:
        $a = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 17 EB 02 CD 20 EB 03 3A 4D 3A FC EB 02 C7 85 E8 00 00 00 00 EB 02 C7 05 EB 02 CD 20 5E EB 02 CD 20 83 C6 3F }
    condition:
        $a at pe.entry_point

}