rule TTP_XOR_QUAD_CurrentVersionRun_5678 {
  strings:
    $key_5678 = { 05 17 [2] 21 19 [2] 0a 35 [2] 24 17 [2] 30 0c [2] 3f 16 [2] 21 0b [2] 23 0a [2] 38 0c [2] 24 0b [2] 38 24 }

  condition:
    any of them
}