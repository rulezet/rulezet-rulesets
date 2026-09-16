rule vox_voxware: VOX
{
    meta:
        author = "Rafa Bono"
        file_info = "VoxWare MetaVoice encoded audio"

    strings:
        $a = {52 49 46 46}

    condition:
       $a at 0
}