import "pe"
rule Turbo_Pascal_3: PEiD
{
    strings:
        $a = { E9 00 00 90 90 CD AB 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 38 35 20 42 4F 52 4C 41 4E 44 20 49 6E 63 02 04 00 }
    condition:
        $a at pe.entry_point

}