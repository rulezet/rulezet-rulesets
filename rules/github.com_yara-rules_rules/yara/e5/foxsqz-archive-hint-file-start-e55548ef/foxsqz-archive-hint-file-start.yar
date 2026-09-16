import "pe"
rule FOXSQZ_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 46 4F 58 53 51 5A }
    condition:
        $a at pe.entry_point

}