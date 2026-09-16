import "pe"
rule Encapsulated_Postscript_graphics_file_v20_EPSF_12_additional: PEiD
{
    strings:
        $a = { 25 21 50 53 2D 41 64 6F 62 65 2D 32 2E 30 20 45 50 53 46 2D 31 2E 32 }
    condition:
        $a at pe.entry_point

}