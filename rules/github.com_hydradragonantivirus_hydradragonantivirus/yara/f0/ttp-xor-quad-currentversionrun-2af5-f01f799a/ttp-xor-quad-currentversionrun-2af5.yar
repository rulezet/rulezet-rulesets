rule TTP_XOR_QUAD_CurrentVersionRun_2af5 {
  strings:
    $key_2af5 = { 79 9a [2] 5d 94 [2] 76 b8 [2] 58 9a [2] 4c 81 [2] 43 9b [2] 5d 86 [2] 5f 87 [2] 44 81 [2] 58 86 [2] 44 a9 }

  condition:
    any of them
}