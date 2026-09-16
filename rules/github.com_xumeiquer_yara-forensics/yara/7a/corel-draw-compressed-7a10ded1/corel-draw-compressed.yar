rule corel_draw_compressed: CDR
{
    meta:
        author = "Joan Bono"
        file_info = "Corel Draw Document Compressed"

    strings:
        $a = {50 4B 03 04}

    condition:
       $a
}