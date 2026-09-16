rule gsm: GSM
{
    meta:
        author = "Rafa Bono"
        file_info = "US Robotics GSM audio"

    strings:
        $a = {52 49 46 46}

    condition:
       $a at 0
}