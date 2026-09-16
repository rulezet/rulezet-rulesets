rule mp3_hd: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "MP3 HD audio"

    strings:
        $a = {49 44 33 03 00 00 00}

    condition:
       $a at 0
}