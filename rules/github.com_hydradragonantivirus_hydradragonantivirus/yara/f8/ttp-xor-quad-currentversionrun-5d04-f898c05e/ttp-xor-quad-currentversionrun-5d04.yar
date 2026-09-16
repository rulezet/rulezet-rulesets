rule TTP_XOR_QUAD_CurrentVersionRun_5d04 {
  strings:
    $key_5d04 = { 0e 6b [2] 2a 65 [2] 01 49 [2] 2f 6b [2] 3b 70 [2] 34 6a [2] 2a 77 [2] 28 76 [2] 33 70 [2] 2f 77 [2] 33 58 }

  condition:
    any of them
}