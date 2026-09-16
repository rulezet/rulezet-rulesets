rule odg: ODG
{
    meta:
        author = "Joan Bono"
        file_info = "Open Document Graphics document"

    strings:
        $a = {50 4B 03 04}

    condition:
       $a
}