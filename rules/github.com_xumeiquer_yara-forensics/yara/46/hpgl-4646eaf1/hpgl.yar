rule hpgl: HPGL
{
    meta:
        author = "Joan Bono"
        file_info = "HP Graphics Language"

    strings:
        $a = {49 4E 3B}

    condition:
       $a
}