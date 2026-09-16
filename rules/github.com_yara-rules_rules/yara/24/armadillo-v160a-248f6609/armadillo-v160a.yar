import "pe"
rule Armadillo_v160a: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
    condition:
        $a at pe.entry_point

}