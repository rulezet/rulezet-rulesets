rule PEiD_00940_JAM_v2_11_ {
  meta:
    description = "[JAM v2.11]"
    ep_only     = "true"

  strings:
    $a = { 50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB }

  condition:
    $a
}