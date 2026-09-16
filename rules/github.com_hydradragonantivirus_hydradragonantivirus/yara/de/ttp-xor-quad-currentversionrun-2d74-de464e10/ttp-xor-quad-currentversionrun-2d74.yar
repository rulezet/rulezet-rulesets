rule TTP_XOR_QUAD_CurrentVersionRun_2d74 {
  strings:
    $key_2d74 = { 7e 1b [2] 5a 15 [2] 71 39 [2] 5f 1b [2] 4b 00 [2] 44 1a [2] 5a 07 [2] 58 06 [2] 43 00 [2] 5f 07 [2] 43 28 }

  condition:
    any of them
}