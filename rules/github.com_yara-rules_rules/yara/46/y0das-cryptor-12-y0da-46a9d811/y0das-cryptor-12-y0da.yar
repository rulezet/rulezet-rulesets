import "pe"
rule y0das_Cryptor_12_y0da: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC }
    condition:
        $a at pe.entry_point

}