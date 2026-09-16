import "pe"
rule HackStop_113_EXE: PEiD
{
    strings:
        $a = { 52 B8 00 30 1E CD 21 86 E0 3D 00 02 73 02 CD 20 0E 1F B4 09 E8 03 00 24 24 EA 5A CD 21 1F 5A }
    condition:
        $a at pe.entry_point

}