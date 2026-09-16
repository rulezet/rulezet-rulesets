import "pe"
rule RAR_Archive: PEiD
{
    strings:
        $a = { 52 61 72 21 }
    condition:
        $a at pe.entry_point

}