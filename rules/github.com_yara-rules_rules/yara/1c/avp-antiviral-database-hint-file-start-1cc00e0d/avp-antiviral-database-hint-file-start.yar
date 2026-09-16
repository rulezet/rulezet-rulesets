import "pe"
rule AVP_Antiviral_Database_Hint_FILE_START: PEiD
{
    strings:
        $a = { 41 56 50 20 41 6E 74 69 76 69 72 61 6C 20 44 61 74 61 62 61 73 65 }
    condition:
        $a at pe.entry_point

}