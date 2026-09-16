rule TTP_XOR_QUAD_CurrentVersionRun_d6fd {
  strings:
    $key_d6fd = { 85 92 [2] a1 9c [2] 8a b0 [2] a4 92 [2] b0 89 [2] bf 93 [2] a1 8e [2] a3 8f [2] b8 89 [2] a4 8e [2] b8 a1 }

  condition:
    any of them
}