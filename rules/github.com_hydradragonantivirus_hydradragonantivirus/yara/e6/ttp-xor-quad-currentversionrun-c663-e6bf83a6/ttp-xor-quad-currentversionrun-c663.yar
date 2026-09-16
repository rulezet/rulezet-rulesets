rule TTP_XOR_QUAD_CurrentVersionRun_c663 {
  strings:
    $key_c663 = { 95 0c [2] b1 02 [2] 9a 2e [2] b4 0c [2] a0 17 [2] af 0d [2] b1 10 [2] b3 11 [2] a8 17 [2] b4 10 [2] a8 3f }

  condition:
    any of them
}