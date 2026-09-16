rule au: AU
{
    meta:
        author = "Rafa Bono"
        file_info = "Audacity Audio"

    strings:
        $a = {64 6E 73 2E}

    condition:
       $a at 0
}