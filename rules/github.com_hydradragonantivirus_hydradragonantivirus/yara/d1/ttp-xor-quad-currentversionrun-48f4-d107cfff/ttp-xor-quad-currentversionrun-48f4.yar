rule TTP_XOR_QUAD_CurrentVersionRun_48f4 {
  strings:
    $key_48f4 = { 1b 9b [2] 3f 95 [2] 14 b9 [2] 3a 9b [2] 2e 80 [2] 21 9a [2] 3f 87 [2] 3d 86 [2] 26 80 [2] 3a 87 [2] 26 a8 }

  condition:
    any of them
}