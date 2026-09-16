rule vmem: VMEM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {53 ff 00 f0}

    condition:
       $a at 0
}