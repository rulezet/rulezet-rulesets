import "pe"
rule Goldeds_Output_text_file: PEiD
{
    strings:
        $a = { C4 20 5B }
    condition:
        $a at pe.entry_point

}