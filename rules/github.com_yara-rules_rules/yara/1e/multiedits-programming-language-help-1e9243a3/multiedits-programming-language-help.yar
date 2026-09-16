import "pe"
rule MultiEdits_Programming_Language_help: PEiD
{
    strings:
        $a = { 0C 2A 20 }
    condition:
        $a at pe.entry_point

}