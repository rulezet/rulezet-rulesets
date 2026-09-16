rule pgf: PGF
{
    meta:
        author = "Joan Bono"
        file_info = "Progressive Graphics File bitmap"

    strings:
        $a = {50 47 46 01 10 00}

    condition:
       $a
}