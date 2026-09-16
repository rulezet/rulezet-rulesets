import "pe"
rule Inset_Systems_IGF_graphics_file: PEiD
{
    strings:
        $a = { 01 80 04 00 01 00 58 00 }
    condition:
        $a at pe.entry_point

}