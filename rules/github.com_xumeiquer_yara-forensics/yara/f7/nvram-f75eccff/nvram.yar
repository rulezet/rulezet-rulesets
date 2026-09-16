rule nvram: NVRAM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {4D 52 56 4E}

    condition:
       $a at 0
}