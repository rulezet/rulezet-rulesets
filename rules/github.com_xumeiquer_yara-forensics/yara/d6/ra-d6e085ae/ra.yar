rule ra: RA
{
    meta:
        author = "Rafa Bono"
        file_info = "Real Audio"

    strings:
        $a = {2E 72 61 FD 00}
        $b = {2E 52 4D 46 00 00 00 12 00}

    condition:
       $a at 0 or $b at 0
}