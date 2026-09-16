rule TTP_XOR_QUAD_CurrentVersionRun_c0e1 {
  strings:
    $key_c0e1 = { 93 8e [2] b7 80 [2] 9c ac [2] b2 8e [2] a6 95 [2] a9 8f [2] b7 92 [2] b5 93 [2] ae 95 [2] b2 92 [2] ae bd }

  condition:
    any of them
}