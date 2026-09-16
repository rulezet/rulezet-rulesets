import "pe"
rule Packman_V10_Brandon_LaCombe_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }
    condition:
        $a at pe.entry_point

}