rule aax: AAX
{
    meta:
        author = "Rafa Bono"
        file_info = "Audible Enhanced Audio"

    strings:
        $a = {00 00 00 24 66 74 79 70 61 61 78 20 00 00 00 01}

    condition:
       $a at 0
}