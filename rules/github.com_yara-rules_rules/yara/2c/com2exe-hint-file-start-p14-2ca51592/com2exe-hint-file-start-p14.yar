import "pe"
rule COM2EXE_Hint_FILE_START_p14: PEiD
{
    strings:
        $a = { F0 FF FE FF }
    condition:
        $a at pe.entry_point

}