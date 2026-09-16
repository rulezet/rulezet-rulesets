rule gzip: gzip
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {1F 8B}
        $b = {1F 8B}

    condition:
    $a at 0 or $b at 0
}