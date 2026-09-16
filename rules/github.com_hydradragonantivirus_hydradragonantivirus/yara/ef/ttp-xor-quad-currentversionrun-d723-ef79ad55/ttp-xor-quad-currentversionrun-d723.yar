rule TTP_XOR_QUAD_CurrentVersionRun_d723 {
  strings:
    $key_d723 = { 84 4c [2] a0 42 [2] 8b 6e [2] a5 4c [2] b1 57 [2] be 4d [2] a0 50 [2] a2 51 [2] b9 57 [2] a5 50 [2] b9 7f }

  condition:
    any of them
}