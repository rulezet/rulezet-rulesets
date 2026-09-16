rule TTP_XOR_QUAD_CurrentVersionRun_2357 {
  strings:
    $key_2357 = { 70 38 [2] 54 36 [2] 7f 1a [2] 51 38 [2] 45 23 [2] 4a 39 [2] 54 24 [2] 56 25 [2] 4d 23 [2] 51 24 [2] 4d 0b }

  condition:
    any of them
}