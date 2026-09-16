rule excel_OrthoTrack: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 56 65 72 73 69 6F 6E 09 }

    condition:
       $a at 0
}