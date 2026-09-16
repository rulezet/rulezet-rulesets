rule TTP_XOR_QUAD_CurrentVersionRun_dff3 {
  strings:
    $key_dff3 = { 8c 9c [2] a8 92 [2] 83 be [2] ad 9c [2] b9 87 [2] b6 9d [2] a8 80 [2] aa 81 [2] b1 87 [2] ad 80 [2] b1 af }

  condition:
    any of them
}