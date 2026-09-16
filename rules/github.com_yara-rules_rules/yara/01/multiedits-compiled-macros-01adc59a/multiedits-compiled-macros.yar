import "pe"
rule MultiEdits_compiled_macros: PEiD
{
    strings:
        $a = { 1E AA }
    condition:
        $a at pe.entry_point

}