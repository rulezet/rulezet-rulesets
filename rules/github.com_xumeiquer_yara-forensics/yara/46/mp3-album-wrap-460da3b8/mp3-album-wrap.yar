rule mp3_album_wrap: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "MP3 AlbumWrap archive"

    strings:
        $a = {49 44 33 03 00 00 00 00 0A 23 54 49 54 32 00 00}

    condition:
       $a at 0
}