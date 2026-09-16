rule TTP_XOR_QUAD_CurrentVersionRun_61e1 {
  strings:
    $key_61e1 = { 32 8e [2] 16 80 [2] 3d ac [2] 13 8e [2] 07 95 [2] 08 8f [2] 16 92 [2] 14 93 [2] 0f 95 [2] 13 92 [2] 0f bd }

  condition:
    any of them
}