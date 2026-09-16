rule vmss: VMSS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {d2 be d2 be 08 00 00 00 66}

    condition:
       $a at 0
}