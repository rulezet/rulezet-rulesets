rule TTP_XOR_QUAD_CurrentVersionRun_3158 {
  strings:
    $key_3158 = { 62 37 [2] 46 39 [2] 6d 15 [2] 43 37 [2] 57 2c [2] 58 36 [2] 46 2b [2] 44 2a [2] 5f 2c [2] 43 2b [2] 5f 04 }

  condition:
    any of them
}