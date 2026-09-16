import "pe"
rule PELOCknt_202: PEiD
{
    strings:
        $a = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD 20 60 EB 03 CD 20 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 04 CD 20 EB 02 EB 02 CD 20 EB 03 CD 20 EA FC EB 03 CD 20 69 E8 00 00 00 00 EB 02 EB 01 EB 01 EB 5E EB 02 CD 20 0F 01 4E }
    condition:
        $a at pe.entry_point

}