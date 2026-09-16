rule TTP_XOR_QUAD_CurrentVersionRun_5d39 {
  strings:
    $key_5d39 = { 0e 56 [2] 2a 58 [2] 01 74 [2] 2f 56 [2] 3b 4d [2] 34 57 [2] 2a 4a [2] 28 4b [2] 33 4d [2] 2f 4a [2] 33 65 }

  condition:
    any of them
}