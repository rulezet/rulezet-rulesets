import "pe"
rule Scitech_Software_Display_Driver_Hint_FILE_START: PEiD
{
    strings:
        $a = { 56 42 45 41 46 2E 44 52 56 }
    condition:
        $a at pe.entry_point

}