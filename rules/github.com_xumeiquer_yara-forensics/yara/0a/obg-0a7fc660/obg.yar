rule obg: OBJ
{
    meta:
        author = "Joan Bono"
        file_info = "AliaslWavefront File Format"

    strings:
        $a = {23 20 4D 61 78 32 4F 62 6A 20 56 65 72 73 69 6F} 
        $b = {23 57 61 76 65 66 72 6F 6E 74 20 4F 42 4A 20 66} 
        $c = {41 43 4D 54 00 00} 
        $d = {23 20 42 6C 65 6E 64 65 72} 

    condition:
       any of them
}