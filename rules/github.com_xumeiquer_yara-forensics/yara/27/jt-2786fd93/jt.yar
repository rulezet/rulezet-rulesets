rule jt: JT
{
    meta:
        author = "Joan Bono"
        file_info = "JT 3D Visualization format"

    strings:
        $a = {56 65 72 73 69 6F 6E 20}

    condition:
       $a
}