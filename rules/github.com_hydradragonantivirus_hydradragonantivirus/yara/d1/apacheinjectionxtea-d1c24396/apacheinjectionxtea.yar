rule apacheInjectionXtea {
  meta:
    description = "Detection for new Apache injection module spotted in wild."
    in_the_wild = true
    reference1 = "http://blog.sucuri.net/2013/06/new-apache-module-injection.html"
    reference2 = "TBD"

  strings:
    $xteaFunction = { 8B 0F 8B 57 04 B8 F3 3A 62 CC 41 89 C0 41 89 C9 41 89 CA 41 C1 E8 0B 41 C1 E2 04 41 C1 E9 05 41 83 E0 03 45 31 D1 46 8B 04 86 41 01 C9 41 01 C0 05 47 86 C8 61 45 31 C8 44 29 C2 49 89 C0 41 83 E0 03 41 89 D1 41 89 D2 46 8B 04 86 41 C1 E9 05 41 C1 E2 04 45 31 D1 41 01 D1 41 01 C0 45 31 C8 44 29 C1 85 C0 75 A3 89 0F 89 57 04 C3 }
    $xteaKey1 = { 4A F5 5E 5E B9 8A E1 63 30 16 B6 15 23 51 66 03 }
    $xteaKey2 = { 68 2C 16 4A 30 A8 14 1F 1E AD 0D 24 E1 0E 10 01 }

  condition:
    $xteaFunction or any of ($xteaKey*)
}