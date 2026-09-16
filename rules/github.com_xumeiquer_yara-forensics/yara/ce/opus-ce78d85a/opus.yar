rule opus: OPUS
{
    meta:
        author = "Rafa Bono"
        file_info = "Opus compressed audio"

    strings:
        $a = {4F 67 67 53}

    condition:
       $a at 0
}