rule TTP_XOR_QUAD_CurrentVersionRun_5319 {
  strings:
    $key_5319 = { 00 76 [2] 24 78 [2] 0f 54 [2] 21 76 [2] 35 6d [2] 3a 77 [2] 24 6a [2] 26 6b [2] 3d 6d [2] 21 6a [2] 3d 45 }

  condition:
    any of them
}