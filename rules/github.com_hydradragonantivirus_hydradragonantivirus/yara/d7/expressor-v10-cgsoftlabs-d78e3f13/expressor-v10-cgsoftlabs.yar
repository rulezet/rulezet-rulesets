import "pe"
rule _eXpressor_v10__CGSoftLabs_ {
  meta:
    description = "eXpressor v1.0 -> CGSoftLabs"

  strings:
    $0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 }

  condition:
    $0 at pe.entry_point
}