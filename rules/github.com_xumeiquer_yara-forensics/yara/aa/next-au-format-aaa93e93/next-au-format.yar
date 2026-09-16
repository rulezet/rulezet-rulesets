rule next_au_format: AU
{
    meta:
        author = "Rafa Bono"
        file_info = "NeXT Audio Format"

    strings:
        $a = {2E 73 6E 64 00 00 00}

    condition:
       $a at 0
}