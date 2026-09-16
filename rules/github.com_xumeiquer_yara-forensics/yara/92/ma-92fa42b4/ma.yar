rule ma: MA
{
    meta:
        author = "Joan Bono"
        file_info = "Maya ASCII Format"

    strings:
        $a = {2F 2F 4D 61 79 61 20 41 53 43 49 49}

    condition:
       $a
}