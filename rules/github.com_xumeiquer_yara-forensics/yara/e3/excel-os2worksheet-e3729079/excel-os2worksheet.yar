rule excel_OS2worksheet: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 09 00 04 00 06 00 }

    condition:
       $a at 0
}