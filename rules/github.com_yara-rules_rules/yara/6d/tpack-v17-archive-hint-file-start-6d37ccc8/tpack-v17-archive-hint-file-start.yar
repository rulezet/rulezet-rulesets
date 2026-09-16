import "pe"
rule TPACK_v17_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 54 50 41 43 ?? 31 2E 37 }
    condition:
        $a at pe.entry_point

}