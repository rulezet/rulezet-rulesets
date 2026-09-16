import "pe"
rule Microsoft_R_Full_text_index_file: PEiD
{
    strings:
        $a = { 6C 6C 2D 74 65 78 74 20 69 6E 64 65 78 }
    condition:
        $a at pe.entry_point

}