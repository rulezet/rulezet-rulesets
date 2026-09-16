import "pe"
rule Limit_Archive: PEiD
{
    strings:
        $a = { 4C 4D 1A }
    condition:
        $a at pe.entry_point

}