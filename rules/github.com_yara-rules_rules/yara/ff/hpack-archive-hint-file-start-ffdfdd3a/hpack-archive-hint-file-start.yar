import "pe"
rule HPACK_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 48 50 41 4B }
    condition:
        $a at pe.entry_point

}