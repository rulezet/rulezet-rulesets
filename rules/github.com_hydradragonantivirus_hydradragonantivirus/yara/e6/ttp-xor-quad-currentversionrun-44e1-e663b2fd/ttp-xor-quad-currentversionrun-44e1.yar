rule TTP_XOR_QUAD_CurrentVersionRun_44e1 {
  strings:
    $key_44e1 = { 17 8e [2] 33 80 [2] 18 ac [2] 36 8e [2] 22 95 [2] 2d 8f [2] 33 92 [2] 31 93 [2] 2a 95 [2] 36 92 [2] 2a bd }

  condition:
    any of them
}