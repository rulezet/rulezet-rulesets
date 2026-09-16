rule msv: MSV
{
    meta:
        author = "Rafa Bono"
        file_info = "Sony Compressed Voice File"

    strings:
        $a = {4D 53 5F 56 4F 49 43 45}

    condition:
       $a at 0
}