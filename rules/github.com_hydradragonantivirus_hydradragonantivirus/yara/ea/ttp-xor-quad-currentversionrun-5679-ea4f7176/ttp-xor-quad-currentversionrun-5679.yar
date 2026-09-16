rule TTP_XOR_QUAD_CurrentVersionRun_5679 {
  strings:
    $key_5679 = { 05 16 [2] 21 18 [2] 0a 34 [2] 24 16 [2] 30 0d [2] 3f 17 [2] 21 0a [2] 23 0b [2] 38 0d [2] 24 0a [2] 38 25 }

  condition:
    any of them
}