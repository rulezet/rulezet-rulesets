rule TTP_XOR_QUAD_CurrentVersionRun_c603 {
  strings:
    $key_c603 = { 95 6c [2] b1 62 [2] 9a 4e [2] b4 6c [2] a0 77 [2] af 6d [2] b1 70 [2] b3 71 [2] a8 77 [2] b4 70 [2] a8 5f }

  condition:
    any of them
}