rule TTP_XOR_QUAD_CurrentVersionRun_40f5 {
  strings:
    $key_40f5 = { 13 9a [2] 37 94 [2] 1c b8 [2] 32 9a [2] 26 81 [2] 29 9b [2] 37 86 [2] 35 87 [2] 2e 81 [2] 32 86 [2] 2e a9 }

  condition:
    any of them
}