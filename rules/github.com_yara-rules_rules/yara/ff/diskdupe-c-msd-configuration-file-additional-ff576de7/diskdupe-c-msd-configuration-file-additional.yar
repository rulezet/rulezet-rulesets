import "pe"
rule DiskDupe_c_MSD_Configuration_file_additional: PEiD
{
    strings:
        $a = { 4D 53 44 20 44 61 74 61 20 56 65 72 73 }
    condition:
        $a at pe.entry_point

}