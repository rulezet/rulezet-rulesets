rule vmdk: VMDK
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {4B 44 4D 56}

    condition:
       $a at 0
}