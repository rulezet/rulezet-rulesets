rule TTP_XOR_QUAD_CurrentVersionRun_1158 {
  strings:
    $key_1158 = { 42 37 [2] 66 39 [2] 4d 15 [2] 63 37 [2] 77 2c [2] 78 36 [2] 66 2b [2] 64 2a [2] 7f 2c [2] 63 2b [2] 7f 04 }

  condition:
    any of them
}