rule TTP_XOR_QUAD_CurrentVersionRun_d603 {
  strings:
    $key_d603 = { 85 6c [2] a1 62 [2] 8a 4e [2] a4 6c [2] b0 77 [2] bf 6d [2] a1 70 [2] a3 71 [2] b8 77 [2] a4 70 [2] b8 5f }

  condition:
    any of them
}