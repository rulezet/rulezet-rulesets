rule dss_v3: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Digital Speech Standard audio (v3)"

    strings:
        $a = {03 64 73 73}

    condition:
       $a at 0
}