rule u3d: U3D
{
    meta:
        author = "Joan Bono"
        file_info = "Universal 3D"

    strings:
        $a = {55 33 44 00}

    condition:
       $a
}