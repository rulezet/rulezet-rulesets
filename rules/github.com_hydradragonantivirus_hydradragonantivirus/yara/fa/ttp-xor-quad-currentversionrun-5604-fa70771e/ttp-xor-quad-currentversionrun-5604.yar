rule TTP_XOR_QUAD_CurrentVersionRun_5604 {
  strings:
    $key_5604 = { 05 6b [2] 21 65 [2] 0a 49 [2] 24 6b [2] 30 70 [2] 3f 6a [2] 21 77 [2] 23 76 [2] 38 70 [2] 24 77 [2] 38 58 }

  condition:
    any of them
}