import "pe"
rule DataBeam_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 30 31 2E 30 31 00 00 04 }
    condition:
        $a at pe.entry_point

}