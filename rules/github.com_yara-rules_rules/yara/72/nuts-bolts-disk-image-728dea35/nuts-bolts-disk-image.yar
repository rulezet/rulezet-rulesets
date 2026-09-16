import "pe"
rule Nuts_Bolts_Disk_Image: PEiD
{
    strings:
        $a = { 4E 42 69 6D }
    condition:
        $a at pe.entry_point

}