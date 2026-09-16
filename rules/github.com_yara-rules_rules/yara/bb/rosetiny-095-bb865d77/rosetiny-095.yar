import "pe"
rule RoseTiny_095: PEiD
{
    strings:
        $a = { 50 53 B4 30 CD 21 86 E0 3D 00 03 73 02 CD 20 06 50 2B C0 8E C0 85 06 0B EA B8 EB 03 EB FC EA 26 81 36 05 00 D8 83 85 06 1C EA B8 EB 03 EB FC EA 26 81 36 0D 00 0B 9E 85 06 2D EA B8 EB 03 EB FC EA 26 81 36 41 00 BF B4 EB 01 81 58 07 50 B8 EB }
    condition:
        $a at pe.entry_point

}