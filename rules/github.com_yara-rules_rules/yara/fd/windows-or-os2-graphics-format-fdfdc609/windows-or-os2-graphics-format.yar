import "pe"
rule Windows_or_OS2_Graphics_format: PEiD
{
    strings:
        $a = { 42 4D }
    condition:
        $a at pe.entry_point

}