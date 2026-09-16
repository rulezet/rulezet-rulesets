rule TTP_XOR_QUAD_CurrentVersionRun_d7d1 {
  strings:
    $key_d7d1 = { 84 be [2] a0 b0 [2] 8b 9c [2] a5 be [2] b1 a5 [2] be bf [2] a0 a2 [2] a2 a3 [2] b9 a5 [2] a5 a2 [2] b9 8d }

  condition:
    any of them
}