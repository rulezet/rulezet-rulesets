rule blend: BLEND
{
    meta:
        author = "Joan Bono"
        file_info = "Blender 3D File"

    strings:
        $a = {42 4C 45 4E 44 45 52}

    condition:
       $a
}