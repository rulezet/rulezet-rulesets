import "pe"
rule GIF89a_Graphics_format: PEiD
{
    strings:
        $a = { 47 49 46 38 39 61 }
    condition:
        $a at pe.entry_point

}