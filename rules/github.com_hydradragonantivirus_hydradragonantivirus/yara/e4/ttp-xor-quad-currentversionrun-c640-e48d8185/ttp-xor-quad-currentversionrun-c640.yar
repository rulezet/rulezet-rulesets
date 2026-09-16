rule TTP_XOR_QUAD_CurrentVersionRun_c640 {
  strings:
    $key_c640 = { 95 2f [2] b1 21 [2] 9a 0d [2] b4 2f [2] a0 34 [2] af 2e [2] b1 33 [2] b3 32 [2] a8 34 [2] b4 33 [2] a8 1c }

  condition:
    any of them
}