rule TTP_XOR_QUAD_CurrentVersionRun_5658 {
  strings:
    $key_5658 = { 05 37 [2] 21 39 [2] 0a 15 [2] 24 37 [2] 30 2c [2] 3f 36 [2] 21 2b [2] 23 2a [2] 38 2c [2] 24 2b [2] 38 04 }

  condition:
    any of them
}