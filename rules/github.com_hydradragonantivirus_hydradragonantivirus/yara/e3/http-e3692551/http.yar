rule http
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = "http" nocase
    condition:
        $a1
}