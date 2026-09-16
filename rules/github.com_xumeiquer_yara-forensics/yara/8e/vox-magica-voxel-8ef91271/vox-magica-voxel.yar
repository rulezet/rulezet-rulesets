rule vox_magica_voxel: VOX
{
    meta:
        author = "Rafa Bono"
        file_info = "MagicaVoxel file format"

    strings:
        $a = {56 4F 58 20}

    condition:
       $a at 0
}