rule BundloreB
{
    meta:
        description = "OSX.Bundlore.B"
    strings:
        $a = {5F 5F 4D 41 5F 41 70 70 44 65 6C 65 67 61 74 65}
        $b = {5F 5F 4D 41 5F 44 65 74 65 63 74 65 64 50 72 6F 64 75 63 74 73 48 61 6E 64 6C 65 72}
        $c = {5F 5F 4D 41 5F 44 6D 67 53 6F 75 72 63 65 52 65 61 64 65 72}
    condition:
        2 of ($a,$b,$c)
}