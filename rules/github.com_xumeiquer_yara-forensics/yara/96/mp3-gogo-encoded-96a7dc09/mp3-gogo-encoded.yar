rule mp3_gogo_encoded: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "GoGo encoded MP3 audio"

    strings:
        $a = {FF FB 90}
        $b = {49 44 33 }

    condition:
       $a at 0 or $b at 0
}