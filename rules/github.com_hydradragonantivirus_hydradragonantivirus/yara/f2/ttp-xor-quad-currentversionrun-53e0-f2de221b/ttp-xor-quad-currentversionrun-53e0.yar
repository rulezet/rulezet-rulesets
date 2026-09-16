rule TTP_XOR_QUAD_CurrentVersionRun_53e0 {
  strings:
    $key_53e0 = { 00 8f [2] 24 81 [2] 0f ad [2] 21 8f [2] 35 94 [2] 3a 8e [2] 24 93 [2] 26 92 [2] 3d 94 [2] 21 93 [2] 3d bc }

  condition:
    any of them
}