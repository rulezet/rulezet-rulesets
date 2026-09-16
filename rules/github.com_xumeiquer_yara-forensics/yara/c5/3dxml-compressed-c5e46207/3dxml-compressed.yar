rule _3dxml_compressed: _3DXML
{
    meta:
        author = "Joan Bono"
        file_info = "3D XML Files Compressed"

    strings:
        $a = {50 4B 03 04}

    condition:
       $a
}