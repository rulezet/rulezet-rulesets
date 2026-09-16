import "pe"
rule AIN_Archive: PEiD
{
    strings:
        $a = { 21 12 00 }
    condition:
        $a at pe.entry_point

}