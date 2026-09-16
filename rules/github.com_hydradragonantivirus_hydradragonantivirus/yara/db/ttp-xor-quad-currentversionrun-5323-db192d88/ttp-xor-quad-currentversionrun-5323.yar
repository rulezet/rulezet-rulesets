rule TTP_XOR_QUAD_CurrentVersionRun_5323 {
  strings:
    $key_5323 = { 00 4c [2] 24 42 [2] 0f 6e [2] 21 4c [2] 35 57 [2] 3a 4d [2] 24 50 [2] 26 51 [2] 3d 57 [2] 21 50 [2] 3d 7f }

  condition:
    any of them
}