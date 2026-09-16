import "pe"
rule HackStop_118_EXE: PEiD
{
    strings:
        $a = { 52 BA EB 04 5A EB FB 9A 1E 52 B8 42 30 CD 21 86 C4 3D FD 02 73 02 CD 20 0E 1F 52 BA EB 04 5A EB FB 9A E8 02 00 24 24 5A B4 09 CD 21 52 BA EB 04 5A EB FB 9A EB 02 D8 88 5A 1F 52 BA EB 04 5A EB FB 9A B0 AD E6 64 52 BA EB 04 5A EB FB 9A FA CD }
    condition:
        $a at pe.entry_point

}