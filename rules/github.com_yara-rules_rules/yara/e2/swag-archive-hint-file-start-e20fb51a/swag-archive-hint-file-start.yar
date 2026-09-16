import "pe"
rule SWAG_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 2D 73 77 31 2D }
    condition:
        $a at pe.entry_point

}