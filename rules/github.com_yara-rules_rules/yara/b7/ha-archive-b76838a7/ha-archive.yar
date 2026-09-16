import "pe"
rule HA_Archive: PEiD
{
    strings:
        $a = { 48 41 }
    condition:
        $a at pe.entry_point

}