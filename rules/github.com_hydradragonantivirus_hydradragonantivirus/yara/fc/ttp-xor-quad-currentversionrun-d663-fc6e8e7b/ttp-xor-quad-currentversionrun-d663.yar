rule TTP_XOR_QUAD_CurrentVersionRun_d663 {
  strings:
    $key_d663 = { 85 0c [2] a1 02 [2] 8a 2e [2] a4 0c [2] b0 17 [2] bf 0d [2] a1 10 [2] a3 11 [2] b8 17 [2] a4 10 [2] b8 3f }

  condition:
    any of them
}