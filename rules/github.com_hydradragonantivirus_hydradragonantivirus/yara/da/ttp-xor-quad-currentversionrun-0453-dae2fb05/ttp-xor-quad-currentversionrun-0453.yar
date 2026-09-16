rule TTP_XOR_QUAD_CurrentVersionRun_0453 {
  strings:
    $key_0453 = { 57 3c [2] 73 32 [2] 58 1e [2] 76 3c [2] 62 27 [2] 6d 3d [2] 73 20 [2] 71 21 [2] 6a 27 [2] 76 20 [2] 6a 0f }

  condition:
    any of them
}