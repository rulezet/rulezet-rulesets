rule TTP_XOR_QUAD_CurrentVersionRun_1e57 {
  strings:
    $key_1e57 = { 4d 38 [2] 69 36 [2] 42 1a [2] 6c 38 [2] 78 23 [2] 77 39 [2] 69 24 [2] 6b 25 [2] 70 23 [2] 6c 24 [2] 70 0b }

  condition:
    any of them
}