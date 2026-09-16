import "pe"
rule PELOCknt_203: PEiD
{
    strings:
        $a = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 01 EB EB 02 CD 20 EB 03 CD 20 EB FC EB 02 C7 85 E8 00 00 00 00 EB 03 CD 20 EA 5E EB 03 CD 20 69 0F 01 4E F4 EB 03 CD 20 EB EB 01 EB }
    condition:
        $a at pe.entry_point

}