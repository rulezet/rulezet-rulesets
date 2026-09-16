rule awb: AWB
{
    meta:
        author = "Rafa Bono"
        file_info = "Adaptive Multi-Rate Wideband ACELP codec"

    strings:
        $a = {23 21 41 4D 52 2D 57 42}

    condition:
       $a at 0
}