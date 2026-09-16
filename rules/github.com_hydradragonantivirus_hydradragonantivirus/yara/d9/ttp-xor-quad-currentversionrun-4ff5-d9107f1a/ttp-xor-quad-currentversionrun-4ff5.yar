rule TTP_XOR_QUAD_CurrentVersionRun_4ff5 {
  strings:
    $key_4ff5 = { 1c 9a [2] 38 94 [2] 13 b8 [2] 3d 9a [2] 29 81 [2] 26 9b [2] 38 86 [2] 3a 87 [2] 21 81 [2] 3d 86 [2] 21 a9 }

  condition:
    any of them
}