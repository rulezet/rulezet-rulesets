rule TTP_XOR_QUAD_CurrentVersionRun_d203 {
  strings:
    $key_d203 = { 81 6c [2] a5 62 [2] 8e 4e [2] a0 6c [2] b4 77 [2] bb 6d [2] a5 70 [2] a7 71 [2] bc 77 [2] a0 70 [2] bc 5f }

  condition:
    any of them
}