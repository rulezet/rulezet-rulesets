rule TTP_XOR_QUAD_CurrentVersionRun_d640 {
  strings:
    $key_d640 = { 85 2f [2] a1 21 [2] 8a 0d [2] a4 2f [2] b0 34 [2] bf 2e [2] a1 33 [2] a3 32 [2] b8 34 [2] a4 33 [2] b8 1c }

  condition:
    any of them
}