import "pe"
rule HackStop_119_build_217: PEiD
{
    strings:
        $a = { 53 BB EB 04 5B EB FB EA 9C 1E 52 B4 30 CD 21 86 C4 3D D6 02 73 02 CD 20 0E 1F 53 BB EB 04 5B EB FB EA E8 02 00 24 24 5A B4 09 CD 21 53 BB EB 04 5B EB FB EA EB 02 D8 88 5A 1F 53 BB EB 04 5B EB FB EA B0 AD E6 64 58 E8 D6 F1 53 BB EB 04 5B EB }
    condition:
        $a at pe.entry_point

}