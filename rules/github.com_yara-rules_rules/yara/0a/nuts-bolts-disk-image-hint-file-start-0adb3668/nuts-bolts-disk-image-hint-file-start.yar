import "pe"
rule Nuts_Bolts_Disk_Image_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4E 42 69 6D }
    condition:
        $a at pe.entry_point

}