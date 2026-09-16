rule TTP_XOR_QUAD_CurrentVersionRun_54e1 {
  strings:
    $key_54e1 = { 07 8e [2] 23 80 [2] 08 ac [2] 26 8e [2] 32 95 [2] 3d 8f [2] 23 92 [2] 21 93 [2] 3a 95 [2] 26 92 [2] 3a bd }

  condition:
    any of them
}