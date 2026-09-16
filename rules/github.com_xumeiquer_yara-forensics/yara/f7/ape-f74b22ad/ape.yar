rule ape: APE
{
    meta:
        author = "Rafa Bono"
        file_info = "Monkey's Audio"

    strings:
        $a = {4D 41 43 20}

    condition:
       $a at 0
}