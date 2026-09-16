import "pe"
rule DrWeb_v400p_Virus_DataBase: PEiD
{
    strings:
        $a = { 49 44 52 57 }
    condition:
        $a at pe.entry_point

}