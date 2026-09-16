rule dss: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Digital Sound Studio module"

    strings:
        $a = {4D 4D 55 32}

    condition:
       $a at 0
}