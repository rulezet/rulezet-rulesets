rule tta: TTA
{
    meta:
        author = "Rafa Bono"
        file_info = "TTA lossless compressed audio"

    strings:
        $a = {54 54 41}

    condition:
       $a at 0
}