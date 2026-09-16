rule TTP_XOR_QUAD_CurrentVersionRun_7755 {
  strings:
    $key_7755 = { 24 3a [2] 00 34 [2] 2b 18 [2] 05 3a [2] 11 21 [2] 1e 3b [2] 00 26 [2] 02 27 [2] 19 21 [2] 05 26 [2] 19 09 }

  condition:
    any of them
}