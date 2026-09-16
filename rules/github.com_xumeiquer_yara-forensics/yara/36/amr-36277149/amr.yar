rule amr: AMR
{
    meta:
        author = "Rafa Bono"
        file_info = "Adaptive Multi Rate Encoded Audio"

    strings:
        $a = {23 21 41 4D 52 0A}

    condition:
       $a at 0
}