import "pe"
rule PEiD_5258_3DMark_Database_file_additional: PEiD
{
    strings:
        $a = { 33 44 4D 61 72 6B 20 44 61 74 61 62 61 73 65 20 46 69 6C 65 }
    condition:
        $a at pe.entry_point

}