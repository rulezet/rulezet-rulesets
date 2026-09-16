rule TTP_XOR_QUAD_CurrentVersionRun_69f5 {
  strings:
    $key_69f5 = { 3a 9a [2] 1e 94 [2] 35 b8 [2] 1b 9a [2] 0f 81 [2] 00 9b [2] 1e 86 [2] 1c 87 [2] 07 81 [2] 1b 86 [2] 07 a9 }

  condition:
    any of them
}