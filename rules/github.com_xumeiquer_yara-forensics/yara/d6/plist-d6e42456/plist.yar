rule plist: PLIST
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 62 70 6c 69 73 74 30 30 }

    condition:
       $a at 0
}