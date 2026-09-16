import "pe"
rule MS_HTML_Help_file: PEiD
{
    strings:
        $a = { 49 54 53 46 }
    condition:
        $a at pe.entry_point

}