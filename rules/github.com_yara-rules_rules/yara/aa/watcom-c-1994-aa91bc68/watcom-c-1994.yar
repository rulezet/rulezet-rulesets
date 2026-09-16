import "pe"
rule Watcom_C_1994: PEiD
{
    strings:
        $a = { FB B9 00 0B 8E C1 26 BB 00 09 83 C3 0F 80 E3 F0 26 89 1E 00 03 26 8C 1E 00 03 01 E3 83 C3 0F 80 E3 F0 8E D1 89 DC 26 89 1E 00 03 89 DA D1 EA D1 EA D1 EA D1 EA 26 80 3E 00 03 00 75 3F 8B 0E 02 00 8C C0 29 C1 39 CA 72 0D BB 01 00 B8 00 00 8C }
    condition:
        $a at pe.entry_point

}