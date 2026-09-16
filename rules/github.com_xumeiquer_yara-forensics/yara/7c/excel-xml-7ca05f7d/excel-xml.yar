rule excel_XML: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 3C 3F 78 6D 6C 20 76 }

    condition:
       $a at 0
}