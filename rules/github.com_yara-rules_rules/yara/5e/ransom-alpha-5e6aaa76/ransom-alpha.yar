rule Ransom_Alpha
{
meta:
description = "Regla para detectar Ransom.Alpha (posibles falsos positivos)"
author = "CCN-CERT"
version = "1.0"
strings:
$a = { 52 00 65 00 61 00 64 00 20 00 4D 00 65 00 20 00 28 00 48 00 6F 00 77 00 20 00 44 00 65 00 63 }
condition:
$a
}