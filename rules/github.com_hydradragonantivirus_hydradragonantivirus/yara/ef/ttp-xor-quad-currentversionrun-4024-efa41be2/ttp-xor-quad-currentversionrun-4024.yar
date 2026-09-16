rule TTP_XOR_QUAD_CurrentVersionRun_4024 {
  strings:
    $key_4024 = { 13 4b [2] 37 45 [2] 1c 69 [2] 32 4b [2] 26 50 [2] 29 4a [2] 37 57 [2] 35 56 [2] 2e 50 [2] 32 57 [2] 2e 78 }

  condition:
    any of them
}