import "pe"
rule N_Joy_13_NEX: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00 }
    condition:
        $a at pe.entry_point

}