rule TTP_XOR_QUAD_CurrentVersionRun_7855 {
  strings:
    $key_7855 = { 2b 3a [2] 0f 34 [2] 24 18 [2] 0a 3a [2] 1e 21 [2] 11 3b [2] 0f 26 [2] 0d 27 [2] 16 21 [2] 0a 26 [2] 16 09 }

  condition:
    any of them
}