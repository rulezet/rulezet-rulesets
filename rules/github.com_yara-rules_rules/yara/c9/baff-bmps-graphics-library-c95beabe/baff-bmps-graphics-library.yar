import "pe"
rule BAFF_BMPs_graphics_library: PEiD
{
    strings:
        $a = { 42 41 46 46 01 00 00 00 }
    condition:
        $a at pe.entry_point

}