import "pe"
rule Macs_StuffIt_Archive: PEiD
{
    strings:
        $a = { 53 49 54 21 00 }
    condition:
        $a at pe.entry_point

}