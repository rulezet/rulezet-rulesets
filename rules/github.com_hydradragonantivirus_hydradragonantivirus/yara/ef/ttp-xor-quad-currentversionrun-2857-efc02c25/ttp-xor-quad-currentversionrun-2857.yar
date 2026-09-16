rule TTP_XOR_QUAD_CurrentVersionRun_2857 {
  strings:
    $key_2857 = { 7b 38 [2] 5f 36 [2] 74 1a [2] 5a 38 [2] 4e 23 [2] 41 39 [2] 5f 24 [2] 5d 25 [2] 46 23 [2] 5a 24 [2] 46 0b }

  condition:
    any of them
}