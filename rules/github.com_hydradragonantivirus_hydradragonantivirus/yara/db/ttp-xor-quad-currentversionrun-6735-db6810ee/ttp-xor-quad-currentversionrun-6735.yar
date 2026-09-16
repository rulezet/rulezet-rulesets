rule TTP_XOR_QUAD_CurrentVersionRun_6735 {
  strings:
    $key_6735 = { 34 5a [2] 10 54 [2] 3b 78 [2] 15 5a [2] 01 41 [2] 0e 5b [2] 10 46 [2] 12 47 [2] 09 41 [2] 15 46 [2] 09 69 }

  condition:
    any of them
}