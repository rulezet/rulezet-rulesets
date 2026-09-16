import "pe"
rule SENs_debug_protection: PEiD
{
    strings:
        $a = { BB 10 00 E8 22 00 BD FE 0F 28 63 29 53 45 4E E8 09 00 98 93 92 8A 80 20 21 52 CB 48 9D BB 00 00 9C 58 23 C5 50 03 C3 C3 B8 00 00 8C DD 03 DD C3 }
    condition:
        $a at pe.entry_point

}