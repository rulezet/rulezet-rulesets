rule mb: MB
{
    meta:
        author = "Joan Bono"
        file_info = "Maya Binary Scene"

    strings:
        $a = {46 4F 52 34}

    condition:
       $a
}