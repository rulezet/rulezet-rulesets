import "pe"
rule Petite_21: PEiD
{
    strings:
        $a = { 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 }
    condition:
        $a at pe.entry_point

}