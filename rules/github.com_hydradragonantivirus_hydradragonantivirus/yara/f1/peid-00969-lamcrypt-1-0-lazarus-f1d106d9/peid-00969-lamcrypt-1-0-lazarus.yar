rule PEiD_00969_LamCrypt_1_0____LaZaRuS_ {
  meta:
    description = "[LamCrypt 1.0 -> LaZaRuS]"
    ep_only     = "false"

  strings:
    $a = { 60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 }

  condition:
    $a
}