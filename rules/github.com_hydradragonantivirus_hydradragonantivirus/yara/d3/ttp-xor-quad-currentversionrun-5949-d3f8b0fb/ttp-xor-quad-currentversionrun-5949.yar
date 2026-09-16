rule TTP_XOR_QUAD_CurrentVersionRun_5949 {
  strings:
    $key_5949 = { 0a 26 [2] 2e 28 [2] 05 04 [2] 2b 26 [2] 3f 3d [2] 30 27 [2] 2e 3a [2] 2c 3b [2] 37 3d [2] 2b 3a [2] 37 15 }

  condition:
    any of them
}