import "pe"
rule Encapsulated_Postscript_graphics_file_v30_EPSF_30_additional: PEiD
{
    strings:
        $a = { 25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 2E 30 }
    condition:
        $a at pe.entry_point

}