rule TTP_XOR_QUAD_CurrentVersionRun_4957 {
  strings:
    $key_4957 = { 1a 38 [2] 3e 36 [2] 15 1a [2] 3b 38 [2] 2f 23 [2] 20 39 [2] 3e 24 [2] 3c 25 [2] 27 23 [2] 3b 24 [2] 27 0b }

  condition:
    any of them
}