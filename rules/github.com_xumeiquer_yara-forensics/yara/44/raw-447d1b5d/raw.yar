rule raw: RAW
{
    meta:
        author = "Rafa Bono"
        file_info = "Rdos Raw OPL Capture music"

    strings:
        $a = {52 41 57 41 44 41 54 41}

    condition:
       $a at 0
}