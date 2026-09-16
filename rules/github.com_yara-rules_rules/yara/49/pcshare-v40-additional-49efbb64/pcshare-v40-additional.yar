import "pe"
rule PcShare_v40_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1 }
    condition:
        $a at pe.entry_point

}