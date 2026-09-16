rule wmf: WMF
{
    meta:
        author = "Joan Bono"
        file_info = "Windows Metafile"

    strings:
        $a = {01 00 09 00}
        $b = {D7 CD C6 9A 00 00}

    condition:
       $a or $b
}