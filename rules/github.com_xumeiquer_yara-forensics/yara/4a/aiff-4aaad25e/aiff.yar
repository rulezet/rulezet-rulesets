rule aiff: AIFF
{
    meta:
        author = "Rafa Bono"
        file_info = "Audio Interchange File Format"

    strings:
        $a = {46 4F 52 4D}

    condition:
       $a at 0
}