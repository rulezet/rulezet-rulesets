rule rar: rar
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {52 61 72 21 1A 07 00}
        $b = {52 61 72 21 1A 07 01 00}

    condition:
    $a at 0 or $b at 0
}