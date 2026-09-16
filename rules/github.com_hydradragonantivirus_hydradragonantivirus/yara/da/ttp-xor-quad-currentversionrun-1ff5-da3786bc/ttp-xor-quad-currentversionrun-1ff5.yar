rule TTP_XOR_QUAD_CurrentVersionRun_1ff5 {
  strings:
    $key_1ff5 = { 4c 9a [2] 68 94 [2] 43 b8 [2] 6d 9a [2] 79 81 [2] 76 9b [2] 68 86 [2] 6a 87 [2] 71 81 [2] 6d 86 [2] 71 a9 }

  condition:
    any of them
}