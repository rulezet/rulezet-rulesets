import "pe"
rule SciFax_Graphics_file: PEiD
{
    strings:
        $a = { 44 54 3D 00 }
    condition:
        $a at pe.entry_point

}