rule anime_music_video: AMV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 52 49 46 46 }

    condition:
       $a at 0
}