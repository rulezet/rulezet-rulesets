rule povray: POVRAY
{
    meta:
        author = "Joan Bono"
        file_info = "Persistence of Vision State File"

    strings:
        $a = {50 4F 56 2D 52 61 79 20 52 65 6E 64 65 72 20 53}

    condition:
       $a
}