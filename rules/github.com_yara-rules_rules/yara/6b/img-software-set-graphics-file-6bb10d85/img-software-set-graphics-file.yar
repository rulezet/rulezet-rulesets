import "pe"
rule Img_Software_Set_graphics_file: PEiD
{
    strings:
        $a = { 53 43 4D 49 20 20 20 31 41 54 }
    condition:
        $a at pe.entry_point

}