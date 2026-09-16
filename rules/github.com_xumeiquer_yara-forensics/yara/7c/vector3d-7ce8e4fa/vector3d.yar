rule vector3d: Vector3D
{
    meta:
        author = "Joan Bono"
        file_info = "VersaCAD Drawing"

    strings:
        $a = {01 00 32 00 28 00 00 00}

    condition:
       $a at 0
}