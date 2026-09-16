import "pe"
rule GOES_graphics_file: PEiD
{
    strings:
        $a = { C8 C4 D9 40 C1 D9 C5 C1 }
    condition:
        $a at pe.entry_point

}