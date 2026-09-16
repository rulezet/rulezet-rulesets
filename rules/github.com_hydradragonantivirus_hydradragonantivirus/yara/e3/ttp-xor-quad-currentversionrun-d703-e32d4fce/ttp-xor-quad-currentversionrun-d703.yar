rule TTP_XOR_QUAD_CurrentVersionRun_d703 {
  strings:
    $key_d703 = { 84 6c [2] a0 62 [2] 8b 4e [2] a5 6c [2] b1 77 [2] be 6d [2] a0 70 [2] a2 71 [2] b9 77 [2] a5 70 [2] b9 5f }

  condition:
    any of them
}