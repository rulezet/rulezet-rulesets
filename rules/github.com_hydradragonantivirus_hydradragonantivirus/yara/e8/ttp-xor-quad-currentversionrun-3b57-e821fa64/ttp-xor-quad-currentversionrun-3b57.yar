rule TTP_XOR_QUAD_CurrentVersionRun_3b57 {
  strings:
    $key_3b57 = { 68 38 [2] 4c 36 [2] 67 1a [2] 49 38 [2] 5d 23 [2] 52 39 [2] 4c 24 [2] 4e 25 [2] 55 23 [2] 49 24 [2] 55 0b }

  condition:
    any of them
}