rule rip: RIP
{
    meta:
        author = "Joan Bono"
        file_info = "Rocky Interlace Picture"

    strings:
        $a = {52 49 50}

    condition:
       $a
}