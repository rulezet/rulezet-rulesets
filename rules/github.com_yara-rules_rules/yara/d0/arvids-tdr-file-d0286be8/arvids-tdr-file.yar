import "pe"
rule ARVIDs_TDR_file: PEiD
{
    strings:
        $a = { 74 00 00 00 }
    condition:
        $a at pe.entry_point

}