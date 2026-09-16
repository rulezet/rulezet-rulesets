import "pe"
rule Pelock_10x: PEiD
{
    strings:
        $a = { 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }
    condition:
        $a at pe.entry_point

}