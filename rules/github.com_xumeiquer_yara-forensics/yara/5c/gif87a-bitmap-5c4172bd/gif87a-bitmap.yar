rule gif87a_bitmap: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 38 37 61 }

    condition:
       $a at 0
}