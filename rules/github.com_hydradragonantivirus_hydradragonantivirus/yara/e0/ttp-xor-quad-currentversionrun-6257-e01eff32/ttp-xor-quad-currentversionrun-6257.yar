rule TTP_XOR_QUAD_CurrentVersionRun_6257 {
  strings:
    $key_6257 = { 31 38 [2] 15 36 [2] 3e 1a [2] 10 38 [2] 04 23 [2] 0b 39 [2] 15 24 [2] 17 25 [2] 0c 23 [2] 10 24 [2] 0c 0b }

  condition:
    any of them
}