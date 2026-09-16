rule TTP_XOR_QUAD_CurrentVersionRun_c673 {
  strings:
    $key_c673 = { 95 1c [2] b1 12 [2] 9a 3e [2] b4 1c [2] a0 07 [2] af 1d [2] b1 00 [2] b3 01 [2] a8 07 [2] b4 00 [2] a8 2f }

  condition:
    any of them
}