import "pe"
rule EXEGuard_13: PEiD
{
    strings:
        $a = { BA 98 02 BF B9 00 EB 01 B8 E8 7F FF 7C 29 79 2F FA EA 1D F5 9E 41 76 E5 D8 FD 5D DD 00 88 1C 25 04 55 55 8C 16 15 0A 38 12 2D 0E 8F EF 10 67 36 AC 34 23 DA 39 95 1C 2F 1C 94 00 29 20 3F A9 3D 38 25 15 39 08 29 A0 E8 98 08 A5 39 06 31 BC 2D }
    condition:
        $a at pe.entry_point

}