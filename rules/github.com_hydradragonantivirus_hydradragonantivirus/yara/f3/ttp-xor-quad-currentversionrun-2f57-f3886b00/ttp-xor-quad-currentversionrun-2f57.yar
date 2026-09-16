rule TTP_XOR_QUAD_CurrentVersionRun_2f57 {
  strings:
    $key_2f57 = { 7c 38 [2] 58 36 [2] 73 1a [2] 5d 38 [2] 49 23 [2] 46 39 [2] 58 24 [2] 5a 25 [2] 41 23 [2] 5d 24 [2] 41 0b }

  condition:
    any of them
}