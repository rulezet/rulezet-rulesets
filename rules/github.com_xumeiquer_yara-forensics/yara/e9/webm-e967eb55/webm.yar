rule webm: WEBM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 1A 45 DF A3 }

    condition:
       $a at 0
}