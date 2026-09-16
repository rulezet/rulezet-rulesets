rule TTP_XOR_QUAD_CurrentVersionRun_0e57 {
  strings:
    $key_0e57 = { 5d 38 [2] 79 36 [2] 52 1a [2] 7c 38 [2] 68 23 [2] 67 39 [2] 79 24 [2] 7b 25 [2] 60 23 [2] 7c 24 [2] 60 0b }

  condition:
    any of them
}