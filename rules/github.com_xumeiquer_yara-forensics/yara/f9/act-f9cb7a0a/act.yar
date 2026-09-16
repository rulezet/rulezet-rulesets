rule act: ACT
{
    meta:
        author = "Rafa Bono"
        file_info = "Cartooners Actor"

    strings:
        $a = {00 10 46 00 00 00 77 07 85 0C}

    condition:
       $a at 0
}