rule hsf: HSF
{
    meta:
        author = "Joan Bono"
        file_info = "HOOPS 3D Stream Format"

    strings:
        $a = {3B 3B 20 48 53 46 20 56}

    condition:
       $a
}