rule TTP_XOR_QUAD_CurrentVersionRun_72f5 {
  strings:
    $key_72f5 = { 21 9a [2] 05 94 [2] 2e b8 [2] 00 9a [2] 14 81 [2] 1b 9b [2] 05 86 [2] 07 87 [2] 1c 81 [2] 00 86 [2] 1c a9 }

  condition:
    any of them
}