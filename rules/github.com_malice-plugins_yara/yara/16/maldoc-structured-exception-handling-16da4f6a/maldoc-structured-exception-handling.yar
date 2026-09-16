rule maldoc_structured_exception_handling
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 00 00 00 00}
        $a2 = {64 A1 00 00 00 00}
    condition:
        any of them
}