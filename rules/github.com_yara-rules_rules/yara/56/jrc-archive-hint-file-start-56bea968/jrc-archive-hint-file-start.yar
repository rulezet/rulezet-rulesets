import "pe"
rule JRC_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4A 52 63 68 69 76 65 }
    condition:
        $a at pe.entry_point

}