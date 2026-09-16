rule gem: GEM
{
    meta:
        author = "Joan Bono"
        file_info = "Graphics Environment Manager"

    strings:
        $a = {FF FF 18}

    condition:
       $a
}