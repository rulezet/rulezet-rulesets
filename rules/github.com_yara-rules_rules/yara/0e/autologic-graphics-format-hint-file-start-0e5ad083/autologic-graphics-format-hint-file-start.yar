import "pe"
rule AutoLogic_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { FF 04 00 07 }
    condition:
        $a at pe.entry_point

}