rule x3d: X3D
{
    meta:
        author = "Joan Bono"
        file_info = "Extensible 3D Vector Graphics"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D}

    condition:
       $a
}