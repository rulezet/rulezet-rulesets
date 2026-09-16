rule ai_compressed: AI
{
    meta:
        author = "Joan Bono"
        file_info = "Adobe Illustrator Comrpessed"

    strings:
        $a = {41 69 02}

    condition:
       $a
}