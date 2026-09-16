import "pe"
rule Turbo_Pascal_Desktop_File_additional: PEiD
{
    strings:
        $a = { 54 75 72 62 6F 20 50 61 73 63 61 6C 20 44 65 73 6B 74 6F 70 }
    condition:
        $a at pe.entry_point

}