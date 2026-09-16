rule TTP_XOR_QUAD_CurrentVersionRun_7655 {
  strings:
    $key_7655 = { 25 3a [2] 01 34 [2] 2a 18 [2] 04 3a [2] 10 21 [2] 1f 3b [2] 01 26 [2] 03 27 [2] 18 21 [2] 04 26 [2] 18 09 }

  condition:
    any of them
}