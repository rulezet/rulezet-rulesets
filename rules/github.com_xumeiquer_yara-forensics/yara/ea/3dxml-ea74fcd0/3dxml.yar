rule _3dxml: _3DXML
{
    meta:
        author = "Joan Bono"
        file_info = "3D XML Files"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31}

    condition:
       $a
}