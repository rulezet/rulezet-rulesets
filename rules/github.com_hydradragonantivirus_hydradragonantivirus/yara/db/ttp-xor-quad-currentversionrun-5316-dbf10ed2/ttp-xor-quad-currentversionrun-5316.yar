rule TTP_XOR_QUAD_CurrentVersionRun_5316 {
  strings:
    $key_5316 = { 00 79 [2] 24 77 [2] 0f 5b [2] 21 79 [2] 35 62 [2] 3a 78 [2] 24 65 [2] 26 64 [2] 3d 62 [2] 21 65 [2] 3d 4a }

  condition:
    any of them
}