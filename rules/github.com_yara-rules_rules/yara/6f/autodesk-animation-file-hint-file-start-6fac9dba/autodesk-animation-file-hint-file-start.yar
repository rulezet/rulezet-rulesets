import "pe"
rule AutoDesk_Animation_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 12 AF ?? ?? 40 01 C8 }
    condition:
        $a at pe.entry_point

}