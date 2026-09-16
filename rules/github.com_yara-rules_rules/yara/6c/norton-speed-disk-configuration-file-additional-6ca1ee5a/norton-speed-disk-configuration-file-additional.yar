import "pe"
rule Norton_Speed_Disk_Configuration_file_additional: PEiD
{
    strings:
        $a = { 4E 6F 72 74 6F 6E 20 53 70 65 65 64 }
    condition:
        $a at pe.entry_point

}