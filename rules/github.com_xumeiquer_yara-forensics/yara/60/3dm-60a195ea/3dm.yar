rule _3dm: _3DM
{
    meta:
        author = "Joan Bono"
        file_info = "3D Model"

    strings:
        $a = {43 61 64 65 6E 74 20 33 44 20 4D 6F 64 65 6C 20} 
        $b = {33 44 20 47 65 6F 6D 65 74 72 79 20 46 69 6C 65} 

    condition:
       $a or $b
}