rule dxf: DXF
{
    meta:
        author = "Joan Bono"
        file_info = "AutoDesk AutoCAD Exchange Format"

    strings:
        $a = {41 75 74 6F 43 41 44 20 42 69 6E 61 72 79 20 44}

    condition:
       $a
}