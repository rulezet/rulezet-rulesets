rule TTP_XOR_QUAD_CurrentVersionRun_6ef4 {
  strings:
    $key_6ef4 = { 3d 9b [2] 19 95 [2] 32 b9 [2] 1c 9b [2] 08 80 [2] 07 9a [2] 19 87 [2] 1b 86 [2] 00 80 [2] 1c 87 [2] 00 a8 }

  condition:
    any of them
}