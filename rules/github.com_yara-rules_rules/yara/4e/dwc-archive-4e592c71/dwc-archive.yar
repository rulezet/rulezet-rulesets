import "pe"
rule DWC_Archive: PEiD
{
    strings:
        $a = { 44 57 43 }
    condition:
        $a at pe.entry_point

}