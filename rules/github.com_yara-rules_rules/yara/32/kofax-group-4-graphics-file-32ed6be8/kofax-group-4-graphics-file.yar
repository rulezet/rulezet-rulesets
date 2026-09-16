import "pe"
rule Kofax_Group_4_graphics_file: PEiD
{
    strings:
        $a = { 2E 4B 46 68 80 00 01 00 }
    condition:
        $a at pe.entry_point

}