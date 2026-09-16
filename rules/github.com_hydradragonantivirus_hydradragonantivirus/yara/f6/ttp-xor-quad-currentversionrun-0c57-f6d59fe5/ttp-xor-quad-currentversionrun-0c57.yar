rule TTP_XOR_QUAD_CurrentVersionRun_0c57 {
  strings:
    $key_0c57 = { 5f 38 [2] 7b 36 [2] 50 1a [2] 7e 38 [2] 6a 23 [2] 65 39 [2] 7b 24 [2] 79 25 [2] 62 23 [2] 7e 24 [2] 62 0b }

  condition:
    any of them
}