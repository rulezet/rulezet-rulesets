import "pe"
rule PassEXE_20: PEiD
{
    strings:
        $a = { 06 1E 0E 0E 07 1F 00 00 00 B9 53 01 87 }
    condition:
        $a at pe.entry_point

}