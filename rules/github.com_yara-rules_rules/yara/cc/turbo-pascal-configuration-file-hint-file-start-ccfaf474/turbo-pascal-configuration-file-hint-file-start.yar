import "pe"
rule Turbo_Pascal_Configuration_File_Hint_FILE_START: PEiD
{
    strings:
        $a = { 54 75 72 62 6F 20 50 61 73 63 61 6C 20 43 6F 6E 66 69 67 75 72 61 74 69 6F 6E }
    condition:
        $a at pe.entry_point

}