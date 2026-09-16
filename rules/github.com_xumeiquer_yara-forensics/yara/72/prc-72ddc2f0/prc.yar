rule prc: PRC
{
    meta:
        author = "Joan Bono"
        file_info = "Picture Gear Bitmap"

    strings:
        $a = {42 69 74 6D 61 70}

    condition:
       $a
}