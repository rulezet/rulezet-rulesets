rule TTP_XOR_QUAD_CurrentVersionRun_5677 {
  strings:
    $key_5677 = { 05 18 [2] 21 16 [2] 0a 3a [2] 24 18 [2] 30 03 [2] 3f 19 [2] 21 04 [2] 23 05 [2] 38 03 [2] 24 04 [2] 38 2b }

  condition:
    any of them
}