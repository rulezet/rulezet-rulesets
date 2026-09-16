import "pe"
rule Immun_12_COM: PEiD
{
    strings:
        $a = { 50 53 51 52 56 57 1E 06 E8 00 00 5E 81 EE A4 09 2E 89 36 00 01 8B FE 81 C7 97 09 2E 8B 1D 2B FB 83 C7 02 81 EF 00 01 8B EF B4 30 CD 21 2E 88 85 63 01 3C 03 72 50 8E 1E 2C 00 8C C8 8E C0 8B EF 2E 8B 3E 00 01 81 C7 75 0D 33 F6 B9 00 20 FC AC }
    condition:
        $a at pe.entry_point

}