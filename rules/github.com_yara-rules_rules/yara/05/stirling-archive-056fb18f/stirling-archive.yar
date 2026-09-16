import "pe"
rule Stirling_Archive: PEiD
{
    strings:
        $a = { 13 5D 65 8C 3A }
    condition:
        $a at pe.entry_point

}