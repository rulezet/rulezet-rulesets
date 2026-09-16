import "pe"
rule Sun_Icon_Graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 2F 2A 20 46 6F 72 6D 61 74 5F 76 65 72 73 69 6F 6E 3D 31 2C }
    condition:
        $a at pe.entry_point

}