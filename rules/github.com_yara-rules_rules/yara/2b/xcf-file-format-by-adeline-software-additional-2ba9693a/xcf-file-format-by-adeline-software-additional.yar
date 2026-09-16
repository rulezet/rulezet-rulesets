import "pe"
rule XCF_File_Format_by_Adeline_Software_additional: PEiD
{
    strings:
        $a = { 46 72 61 6D 65 4C 65 6E F4 0F }
    condition:
        $a at pe.entry_point

}