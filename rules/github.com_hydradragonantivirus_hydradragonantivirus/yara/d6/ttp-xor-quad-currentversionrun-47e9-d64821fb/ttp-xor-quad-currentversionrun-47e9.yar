rule TTP_XOR_QUAD_CurrentVersionRun_47e9 {
  strings:
    $key_47e9 = { 14 86 [2] 30 88 [2] 1b a4 [2] 35 86 [2] 21 9d [2] 2e 87 [2] 30 9a [2] 32 9b [2] 29 9d [2] 35 9a [2] 29 b5 }

  condition:
    any of them
}