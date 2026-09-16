import "pe"
rule CAN_Crunched_ANsi_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { CA 01 }
    condition:
        $a at pe.entry_point

}