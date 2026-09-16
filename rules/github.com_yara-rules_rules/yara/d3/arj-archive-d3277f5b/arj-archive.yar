import "pe"
rule ARJ_Archive: PEiD
{
    strings:
        $a = { 60 EA }
    condition:
        $a at pe.entry_point

}