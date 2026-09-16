rule m4a: M4A
{
    meta:
        author = "Rafa Bono"
        file_info = "Apple Lossless Audio Codec"

    strings:
        $a = {00 00 00 20 66 74 79 70 4D 34 41 20 00 00 00 00}

    condition:
       $a at 0
}