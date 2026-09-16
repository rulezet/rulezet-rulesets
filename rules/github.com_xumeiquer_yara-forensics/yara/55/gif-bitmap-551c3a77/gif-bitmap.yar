rule gif_bitmap: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 }

    condition:
       $a at 0
}