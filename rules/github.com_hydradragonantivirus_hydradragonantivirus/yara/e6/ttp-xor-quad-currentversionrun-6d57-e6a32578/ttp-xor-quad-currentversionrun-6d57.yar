rule TTP_XOR_QUAD_CurrentVersionRun_6d57 {
  strings:
    $key_6d57 = { 3e 38 [2] 1a 36 [2] 31 1a [2] 1f 38 [2] 0b 23 [2] 04 39 [2] 1a 24 [2] 18 25 [2] 03 23 [2] 1f 24 [2] 03 0b }

  condition:
    any of them
}