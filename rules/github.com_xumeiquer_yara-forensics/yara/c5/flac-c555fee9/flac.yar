rule flac: FLAC
{
    meta:
        author = "Rafa Bono"
        file_info = "Free Lossless Audio Codec"

    strings:
        $a = {66 4C 61 43}

    condition:
       $a at 0
}