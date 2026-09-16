rule TTP_XOR_QUAD_CurrentVersionRun_07e4 {
  strings:
    $key_07e4 = { 54 8b [2] 70 85 [2] 5b a9 [2] 75 8b [2] 61 90 [2] 6e 8a [2] 70 97 [2] 72 96 [2] 69 90 [2] 75 97 [2] 69 b8 }

  condition:
    any of them
}