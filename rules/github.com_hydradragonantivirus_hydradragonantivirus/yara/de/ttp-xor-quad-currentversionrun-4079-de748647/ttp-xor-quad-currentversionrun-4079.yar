rule TTP_XOR_QUAD_CurrentVersionRun_4079 {
  strings:
    $key_4079 = { 13 16 [2] 37 18 [2] 1c 34 [2] 32 16 [2] 26 0d [2] 29 17 [2] 37 0a [2] 35 0b [2] 2e 0d [2] 32 0a [2] 2e 25 }

  condition:
    any of them
}