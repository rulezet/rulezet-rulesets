rule gif89a_bitmap: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 38 39 61 }

    condition:
       $a at 0
}