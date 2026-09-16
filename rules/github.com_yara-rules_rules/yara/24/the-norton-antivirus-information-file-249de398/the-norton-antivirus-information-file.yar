import "pe"
rule The_Norton_Antivirus_Information_file: PEiD
{
    strings:
        $a = { 54 68 65 20 4E 6F 72 74 6F 6E 20 41 6E 74 69 56 69 72 75 73 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 46 69 6C 65 }
    condition:
        $a at pe.entry_point

}