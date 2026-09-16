rule TTP_XOR_QUAD_CurrentVersionRun_411a {
  strings:
    $key_411a = { 12 75 [2] 36 7b [2] 1d 57 [2] 33 75 [2] 27 6e [2] 28 74 [2] 36 69 [2] 34 68 [2] 2f 6e [2] 33 69 [2] 2f 46 }

  condition:
    any of them
}