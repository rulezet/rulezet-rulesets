rule Ransom_Satana
{
    meta:
        description = "Regla para detectar Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 21 00 73 00 61 00 74 00 61 00 6E 00 61 00 21 00 2E 00 74 00 78 00 74 00 00 }
        $b = { 74 67 77 79 75 67 77 71 }
        $c = { 53 77 76 77 6E 67 75 }
        $d = { 45 6E 75 6D 4C 6F 63 61 6C 52 65 73 }
        $e = { 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 57 00 }
        $f = { 21 53 41 54 41 4E 41 21 }
    condition:
        $b or $c and $d and $a and $e and $f
}