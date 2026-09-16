rule excel_2007: XLSX
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 50 4b 03 04 }

    condition:
       $a at 0
}