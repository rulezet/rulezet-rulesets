rule TTP_XOR_QUAD_CurrentVersionRun_53fd {
  strings:
    $key_53fd = { 00 92 [2] 24 9c [2] 0f b0 [2] 21 92 [2] 35 89 [2] 3a 93 [2] 24 8e [2] 26 8f [2] 3d 89 [2] 21 8e [2] 3d a1 }

  condition:
    any of them
}