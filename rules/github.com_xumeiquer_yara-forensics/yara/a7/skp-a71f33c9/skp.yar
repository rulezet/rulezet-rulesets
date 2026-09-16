rule skp: SKP
{
    meta:
        author = "Joan Bono"
        file_info = "Google SketchUp"

    strings:
        $a = {FF FE FF 0E 53 00 6B 00 65 00 74 00 63 00 68 00}

    condition:
       $a
}