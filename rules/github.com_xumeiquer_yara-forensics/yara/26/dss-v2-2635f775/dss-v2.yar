rule dss_v2: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Digital Speech Standard audio (v2)"

    strings:
        $a = {02 64 73 73}

    condition:
       $a at 0
}