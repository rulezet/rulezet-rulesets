rule TTP_XOR_QUAD_CurrentVersionRun_53e6 {
  strings:
    $key_53e6 = { 00 89 [2] 24 87 [2] 0f ab [2] 21 89 [2] 35 92 [2] 3a 88 [2] 24 95 [2] 26 94 [2] 3d 92 [2] 21 95 [2] 3d ba }

  condition:
    any of them
}