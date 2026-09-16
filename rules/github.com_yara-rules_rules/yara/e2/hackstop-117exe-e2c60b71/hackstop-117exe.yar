import "pe"
rule HackStop_117EXE: PEiD
{
    strings:
        $a = { 52 B8 02 30 1E CD 21 86 E0 3D FE 02 73 02 CD 20 0E 1F B4 09 E8 03 00 24 24 EA 5A CD 21 EB 02 D8 88 1F 5A 53 BB EB 04 5B EB FB 9A B4 30 CD 21 FA 8B EC 8B 46 FA 05 0C 00 FF E0 81 EB 02 EB F0 81 46 FA 1A 00 83 EC 06 CF 82 B0 AD E6 64 53 BB EB }
    condition:
        $a at pe.entry_point

}