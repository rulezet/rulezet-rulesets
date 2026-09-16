import "pe"
rule eXpressor_v12x: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 64 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E }
    condition:
        $a at pe.entry_point

}