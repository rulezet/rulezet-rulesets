rule corel_draw_graohic: CDR
{
    meta:
        author = "Joan Bono"
        file_info = "Corel Draw Document"

    strings:
        $a = {52 49 46 46}

    condition:
       $a
}