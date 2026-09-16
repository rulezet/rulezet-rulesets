import "pe"
rule Vx_Einstein: PEiD
{
    strings:
        $a = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42 }
    condition:
        $a at pe.entry_point

}