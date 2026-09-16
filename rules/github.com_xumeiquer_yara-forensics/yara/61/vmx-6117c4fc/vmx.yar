rule vmx: VMX
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {2E 65 6E 63 6F 64 69 6E 67 20 3D 20 22}

    condition:
       $a at 0
}