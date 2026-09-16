rule TTP_XOR_QUAD_CurrentVersionRun_4074 {
  strings:
    $key_4074 = { 13 1b [2] 37 15 [2] 1c 39 [2] 32 1b [2] 26 00 [2] 29 1a [2] 37 07 [2] 35 06 [2] 2e 00 [2] 32 07 [2] 2e 28 }

  condition:
    any of them
}