rule dream_station_1_module: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Dream Station 1.0 module"

    strings:
        $a = {44 53 46 6D 74 31 0D 0A}

    condition:
       $a at 0
}