import "pe"
rule eXpressor_Version_1501: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 50 02 00 00 53 56 57 83 A5 D0 FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 }
    condition:
        $a at pe.entry_point

}