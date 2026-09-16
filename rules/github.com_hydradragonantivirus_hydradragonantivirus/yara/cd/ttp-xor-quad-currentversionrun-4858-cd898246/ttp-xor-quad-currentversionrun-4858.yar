rule TTP_XOR_QUAD_CurrentVersionRun_4858 {
  strings:
    $key_4858 = { 1b 37 [2] 3f 39 [2] 14 15 [2] 3a 37 [2] 2e 2c [2] 21 36 [2] 3f 2b [2] 3d 2a [2] 26 2c [2] 3a 2b [2] 26 04 }

  condition:
    any of them
}