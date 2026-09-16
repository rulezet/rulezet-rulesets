import "pe"
rule eXPressor_V12_CGSoftLabs: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }
    condition:
        $a at pe.entry_point

}