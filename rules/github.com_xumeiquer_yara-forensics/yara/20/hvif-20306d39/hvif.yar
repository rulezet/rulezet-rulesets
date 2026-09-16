rule hvif: HVIF
{
    meta:
        author = "Joan Bono"
        file_info = "Haiku Vector Icon Format"

    strings:
        $a = {6E 63 69 66}

    condition:
       $a
}