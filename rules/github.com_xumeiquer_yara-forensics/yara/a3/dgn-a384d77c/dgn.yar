rule dgn: DGN
{
    meta:
        author = "Joan Bono"
        file_info = "Bentley MicroStation CAD drawing"

    strings:
        $a = {D0 CF 11 E0 A1 B1 1A E1 00}

    condition:
       $a
}