import "pe"
rule Borland_Graphics_Interface_Driver_Hint_FILE_START: PEiD
{
    strings:
        $a = { 46 42 47 44 }
    condition:
        $a at pe.entry_point

}