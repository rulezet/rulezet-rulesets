rule TTP_XOR_QUAD_CurrentVersionRun_7d57 {
  strings:
    $key_7d57 = { 2e 38 [2] 0a 36 [2] 21 1a [2] 0f 38 [2] 1b 23 [2] 14 39 [2] 0a 24 [2] 08 25 [2] 13 23 [2] 0f 24 [2] 13 0b }

  condition:
    any of them
}