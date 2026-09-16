import "pe"
rule eXPressor_v15x_CGSoftLabs_h_additional: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 58 02 00 00 53 56 57 83 A5 CC FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C 01 75 23 }
    condition:
        $a at pe.entry_point

}