rule TTP_XOR_QUAD_CurrentVersionRun_0375 {
  strings:
    $key_0375 = { 50 1a [2] 74 14 [2] 5f 38 [2] 71 1a [2] 65 01 [2] 6a 1b [2] 74 06 [2] 76 07 [2] 6d 01 [2] 71 06 [2] 6d 29 }

  condition:
    any of them
}