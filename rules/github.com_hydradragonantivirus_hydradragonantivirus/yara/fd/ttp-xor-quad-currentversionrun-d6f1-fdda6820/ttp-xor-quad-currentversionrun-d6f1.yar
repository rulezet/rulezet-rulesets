rule TTP_XOR_QUAD_CurrentVersionRun_d6f1 {
  strings:
    $key_d6f1 = { 85 9e [2] a1 90 [2] 8a bc [2] a4 9e [2] b0 85 [2] bf 9f [2] a1 82 [2] a3 83 [2] b8 85 [2] a4 82 [2] b8 ad }

  condition:
    any of them
}