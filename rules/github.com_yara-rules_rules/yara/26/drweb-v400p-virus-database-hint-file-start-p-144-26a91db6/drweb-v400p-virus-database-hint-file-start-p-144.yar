import "pe"
rule DrWeb_v400p_Virus_DataBase_Hint_FILE_START_p_144: PEiD
{
    strings:
        $a = { 49 44 52 57 }
    condition:
        $a at pe.entry_point

}