rule dwf: DWF
{
    meta:
        author = "Joan Bono"
        file_info = "AutoDesk Design Web Format"

    strings:
        $a = {28 44 57 46 20 56}

    condition:
       $a
}