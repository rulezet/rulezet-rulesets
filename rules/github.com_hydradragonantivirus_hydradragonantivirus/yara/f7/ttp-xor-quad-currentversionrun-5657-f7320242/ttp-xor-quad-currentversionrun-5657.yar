rule TTP_XOR_QUAD_CurrentVersionRun_5657 {
  strings:
    $key_5657 = { 05 38 [2] 21 36 [2] 0a 1a [2] 24 38 [2] 30 23 [2] 3f 39 [2] 21 24 [2] 23 25 [2] 38 23 [2] 24 24 [2] 38 0b }

  condition:
    any of them
}