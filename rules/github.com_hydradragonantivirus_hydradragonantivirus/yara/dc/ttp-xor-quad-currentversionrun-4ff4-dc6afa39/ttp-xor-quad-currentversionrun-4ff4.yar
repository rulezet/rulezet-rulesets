rule TTP_XOR_QUAD_CurrentVersionRun_4ff4 {
  strings:
    $key_4ff4 = { 1c 9b [2] 38 95 [2] 13 b9 [2] 3d 9b [2] 29 80 [2] 26 9a [2] 38 87 [2] 3a 86 [2] 21 80 [2] 3d 87 [2] 21 a8 }

  condition:
    any of them
}