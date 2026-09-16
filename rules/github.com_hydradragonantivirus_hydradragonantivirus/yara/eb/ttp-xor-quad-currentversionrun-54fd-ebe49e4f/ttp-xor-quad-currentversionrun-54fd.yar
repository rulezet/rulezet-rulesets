rule TTP_XOR_QUAD_CurrentVersionRun_54fd {
  strings:
    $key_54fd = { 07 92 [2] 23 9c [2] 08 b0 [2] 26 92 [2] 32 89 [2] 3d 93 [2] 23 8e [2] 21 8f [2] 3a 89 [2] 26 8e [2] 3a a1 }

  condition:
    any of them
}