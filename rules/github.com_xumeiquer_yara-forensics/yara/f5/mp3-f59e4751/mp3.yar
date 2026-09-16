rule mp3: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "MP3 Audio"

    strings:
        $a = {49 44 33}

    condition:
       $a at 0
}