rule TTP_XOR_QUAD_CurrentVersionRun_4679 {
  strings:
    $key_4679 = { 15 16 [2] 31 18 [2] 1a 34 [2] 34 16 [2] 20 0d [2] 2f 17 [2] 31 0a [2] 33 0b [2] 28 0d [2] 34 0a [2] 28 25 }

  condition:
    any of them
}