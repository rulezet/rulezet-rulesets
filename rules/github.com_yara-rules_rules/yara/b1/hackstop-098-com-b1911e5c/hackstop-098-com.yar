import "pe"
rule HackStop_098_COM: PEiD
{
    strings:
        $a = { 50 B4 30 CD 21 86 E0 3D 00 03 73 02 CD 20 EB 02 4C 8F 50 55 52 8C D2 FA 50 B8 EB 04 58 EB FB 9A 8C C8 8E D0 EB 02 62 8F 8B EC BC 03 00 2E 85 06 D1 F6 B8 EB 03 EB FC EA 83 FC 03 74 02 FA F4 2E 85 06 E3 F6 B8 EB 03 EB FC EA 33 C0 FA 8E D0 BC }
    condition:
        $a at pe.entry_point

}