import "pe"
rule Microsoft_C: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 ?? B8 }
    condition:
        $a at pe.entry_point

}