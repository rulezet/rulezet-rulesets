import "pe"
rule UFA_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 55 46 41 C6 D2 C1 00 00 }
    condition:
        $a at pe.entry_point

}