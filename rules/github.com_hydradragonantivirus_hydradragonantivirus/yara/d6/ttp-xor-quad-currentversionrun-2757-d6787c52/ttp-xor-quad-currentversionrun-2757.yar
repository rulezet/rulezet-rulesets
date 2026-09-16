rule TTP_XOR_QUAD_CurrentVersionRun_2757 {
  strings:
    $key_2757 = { 74 38 [2] 50 36 [2] 7b 1a [2] 55 38 [2] 41 23 [2] 4e 39 [2] 50 24 [2] 52 25 [2] 49 23 [2] 55 24 [2] 49 0b }

  condition:
    any of them
}