rule TTP_XOR_QUAD_CurrentVersionRun_5315 {
  strings:
    $key_5315 = { 00 7a [2] 24 74 [2] 0f 58 [2] 21 7a [2] 35 61 [2] 3a 7b [2] 24 66 [2] 26 67 [2] 3d 61 [2] 21 66 [2] 3d 49 }

  condition:
    any of them
}