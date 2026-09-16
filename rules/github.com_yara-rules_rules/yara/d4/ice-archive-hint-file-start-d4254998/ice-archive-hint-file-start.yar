import "pe"
rule ICE_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 2D 6C 68 ?? 2D }
    condition:
        $a at pe.entry_point

}