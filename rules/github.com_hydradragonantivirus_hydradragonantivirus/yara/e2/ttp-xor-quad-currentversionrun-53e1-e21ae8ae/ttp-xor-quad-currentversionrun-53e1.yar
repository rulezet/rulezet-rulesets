rule TTP_XOR_QUAD_CurrentVersionRun_53e1 {
  strings:
    $key_53e1 = { 00 8e [2] 24 80 [2] 0f ac [2] 21 8e [2] 35 95 [2] 3a 8f [2] 24 92 [2] 26 93 [2] 3d 95 [2] 21 92 [2] 3d bd }

  condition:
    any of them
}