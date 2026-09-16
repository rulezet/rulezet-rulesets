import "pe"
rule ASYLUM_Music_File_v10: PEiD
{
    strings:
        $a = { 41 53 59 4C 55 4D 20 4D 75 73 69 63 20 46 6F 72 6D 61 74 20 56 31 2E 30 00 }
    condition:
        $a at pe.entry_point

}