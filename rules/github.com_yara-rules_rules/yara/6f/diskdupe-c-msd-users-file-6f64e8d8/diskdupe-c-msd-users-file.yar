import "pe"
rule DiskDupe_c_MSD_Users_file: PEiD
{
    strings:
        $a = { 4D 53 44 20 55 73 65 72 73 20 56 65 72 73 69 6F 6E }
    condition:
        $a at pe.entry_point

}