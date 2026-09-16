rule excel_2003: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 00 }

    condition:
       $a at 0
}