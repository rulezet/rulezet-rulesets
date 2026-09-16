rule Ransom_Petya {
meta:
    description = "Regla para detectar Ransom.Petya con md5 AF2379CC4D607A45AC44D62135FB7015"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
    $a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
    $a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }
condition:
    all of them
}