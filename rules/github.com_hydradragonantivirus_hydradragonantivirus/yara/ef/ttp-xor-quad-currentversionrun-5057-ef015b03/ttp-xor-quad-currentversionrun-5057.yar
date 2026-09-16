rule TTP_XOR_QUAD_CurrentVersionRun_5057 {
  strings:
    $key_5057 = { 03 38 [2] 27 36 [2] 0c 1a [2] 22 38 [2] 36 23 [2] 39 39 [2] 27 24 [2] 25 25 [2] 3e 23 [2] 22 24 [2] 3e 0b }

  condition:
    any of them
}