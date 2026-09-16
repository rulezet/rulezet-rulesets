import "pe"
rule Mess_107_EXE: PEiD
{
    strings:
        $a = { 4D 45 53 53 B9 FF FF 83 C4 04 F3 26 AC E3 46 EB 50 0D 0A 0D 0A 53 74 6F 6E 65 68 65 61 64 27 73 20 4D 45 53 53 20 76 31 2E 30 37 20 FE 20 52 65 67 67 65 64 20 74 6F 20 }
    condition:
        $a at pe.entry_point

}