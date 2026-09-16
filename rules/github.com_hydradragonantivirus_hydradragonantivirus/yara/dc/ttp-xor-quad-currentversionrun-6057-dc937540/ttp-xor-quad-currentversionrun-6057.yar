rule TTP_XOR_QUAD_CurrentVersionRun_6057 {
  strings:
    $key_6057 = { 33 38 [2] 17 36 [2] 3c 1a [2] 12 38 [2] 06 23 [2] 09 39 [2] 17 24 [2] 15 25 [2] 0e 23 [2] 12 24 [2] 0e 0b }

  condition:
    any of them
}