import "pe"
rule TElock_v098b1_Modifly_by_forgothexer: PEiD
{
    strings:
        $a = { 9C 6A 03 73 0B EB 02 75 75 }
    condition:
        $a at pe.entry_point

}