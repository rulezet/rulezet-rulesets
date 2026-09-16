import "pe"
rule MultiEdits_compiled_macros_Hint_FILE_START: PEiD
{
    strings:
        $a = { 1E AA }
    condition:
        $a at pe.entry_point

}