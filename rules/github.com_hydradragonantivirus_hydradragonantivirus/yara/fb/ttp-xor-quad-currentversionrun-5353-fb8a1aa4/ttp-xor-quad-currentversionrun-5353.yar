rule TTP_XOR_QUAD_CurrentVersionRun_5353 {
  strings:
    $key_5353 = { 00 3c [2] 24 32 [2] 0f 1e [2] 21 3c [2] 35 27 [2] 3a 3d [2] 24 20 [2] 26 21 [2] 3d 27 [2] 21 20 [2] 3d 0f }

  condition:
    any of them
}