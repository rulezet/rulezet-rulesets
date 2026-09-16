rule Ransom_Satana_Dropper
{
    meta:
        description = "Regla para detectar el dropper de Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 25 73 2D 54 72 79 45 78 63 65 70 74 }
        $b = { 64 3A 5C 6C 62 65 74 77 6D 77 79 5C 75 69 6A 65 75 71 70 6C 66 77 75 62 2E 70 64 62 }
        $c = { 71 66 6E 74 76 74 68 62 }
    condition:
        all of them
}