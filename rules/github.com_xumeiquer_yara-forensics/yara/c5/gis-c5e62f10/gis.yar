rule gis: GIS
{
    meta:
        author = "Joan Bono"
        file_info = "Erdas bitmap"

    strings:
        $a = {48 45 41 44 37 34 00 00 03 00 00 00 00 00 00 00}

    condition:
       $a
}