import "pe"
rule Armadillo_v190b3_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
    condition:
        $a at pe.entry_point

}