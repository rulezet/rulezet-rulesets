rule TTP_XOR_QUAD_CurrentVersionRun_5336 {
  strings:
    $key_5336 = { 00 59 [2] 24 57 [2] 0f 7b [2] 21 59 [2] 35 42 [2] 3a 58 [2] 24 45 [2] 26 44 [2] 3d 42 [2] 21 45 [2] 3d 6a }

  condition:
    any of them
}