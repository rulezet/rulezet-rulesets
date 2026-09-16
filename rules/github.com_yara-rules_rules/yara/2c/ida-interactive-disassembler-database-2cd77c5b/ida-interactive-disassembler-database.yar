import "pe"
rule IDA_Interactive_Disassembler_database: PEiD
{
    strings:
        $a = { 49 44 41 }
    condition:
        $a at pe.entry_point

}