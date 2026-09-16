rule xar: XAR
{
    meta:
        author = "Joan Bono"
        file_info = "Xara vector drawing"

    strings:
        $a = {58 41 52 41 A3 A3 0D}

    condition:
       $a
}