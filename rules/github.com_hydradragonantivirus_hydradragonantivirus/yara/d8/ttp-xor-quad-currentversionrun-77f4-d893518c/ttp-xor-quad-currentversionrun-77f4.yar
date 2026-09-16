rule TTP_XOR_QUAD_CurrentVersionRun_77f4 {
  strings:
    $key_77f4 = { 24 9b [2] 00 95 [2] 2b b9 [2] 05 9b [2] 11 80 [2] 1e 9a [2] 00 87 [2] 02 86 [2] 19 80 [2] 05 87 [2] 19 a8 }

  condition:
    any of them
}