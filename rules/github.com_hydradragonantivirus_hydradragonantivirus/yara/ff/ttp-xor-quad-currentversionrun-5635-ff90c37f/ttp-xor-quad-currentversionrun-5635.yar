rule TTP_XOR_QUAD_CurrentVersionRun_5635 {
  strings:
    $key_5635 = { 05 5a [2] 21 54 [2] 0a 78 [2] 24 5a [2] 30 41 [2] 3f 5b [2] 21 46 [2] 23 47 [2] 38 41 [2] 24 46 [2] 38 69 }

  condition:
    any of them
}