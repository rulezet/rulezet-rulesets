import "pe"
rule IDA_Interactive_Disassembler_database_Hint_FILE_START: PEiD
{
    strings:
        $a = { 49 44 41 }
    condition:
        $a at pe.entry_point

}