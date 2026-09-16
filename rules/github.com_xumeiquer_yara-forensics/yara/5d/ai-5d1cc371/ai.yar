rule ai: AI
{
    meta:
        author = "Joan Bono"
        file_info = "Adobe Illustrator"

    strings:
        $a = {25 21 50 53 2D}

    condition:
       $a
}