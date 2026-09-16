rule PEiD_00960_kkrunchy_v0_17____F__Giesen_ {
  meta:
    description = "[kkrunchy v0.17 -> F. Giesen]"
    ep_only     = "false"

  strings:
    $a = { FC FF 4D 08 31 D2 8D 7D 30 BE }

  condition:
    $a
}