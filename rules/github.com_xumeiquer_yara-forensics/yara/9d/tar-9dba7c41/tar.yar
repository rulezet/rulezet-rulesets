rule tar: tar
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {75 73 74 61 72 00 30 30}
        $b = {75 73 74 61 72 20 20 00}

    condition:
    $a at 0 or $b at 0
}