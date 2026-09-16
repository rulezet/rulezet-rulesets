rule PEiD_00982_LGLZ_v1_04__com_ {
  meta:
    description = "[LGLZ v1.04 [com]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 3B FC 72 19 B4 09 BA 12 01 CD 21 B4 4C CD 21 }

  condition:
    $a
}