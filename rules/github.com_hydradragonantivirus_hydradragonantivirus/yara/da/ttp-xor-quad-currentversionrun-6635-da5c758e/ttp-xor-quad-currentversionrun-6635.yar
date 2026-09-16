rule TTP_XOR_QUAD_CurrentVersionRun_6635 {
  strings:
    $key_6635 = { 35 5a [2] 11 54 [2] 3a 78 [2] 14 5a [2] 00 41 [2] 0f 5b [2] 11 46 [2] 13 47 [2] 08 41 [2] 14 46 [2] 08 69 }

  condition:
    any of them
}