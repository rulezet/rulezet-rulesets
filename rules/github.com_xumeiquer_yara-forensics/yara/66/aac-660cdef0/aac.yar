rule aac: AAC
{
    meta:
        author = "Rafa Bono"
        file_info = "Advanced Audio Coding"

    strings:
        $a = {41 41 43 00 01 00}

    condition:
       $a at 0
}