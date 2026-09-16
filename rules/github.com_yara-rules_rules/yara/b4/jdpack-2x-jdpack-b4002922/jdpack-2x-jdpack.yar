import "pe"
rule JDPack_2x_JDPack: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }
    condition:
        $a at pe.entry_point

}