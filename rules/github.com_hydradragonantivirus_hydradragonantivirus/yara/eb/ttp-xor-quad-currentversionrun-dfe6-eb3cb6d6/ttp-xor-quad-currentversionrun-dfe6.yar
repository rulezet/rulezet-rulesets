rule TTP_XOR_QUAD_CurrentVersionRun_dfe6 {
  strings:
    $key_dfe6 = { 8c 89 [2] a8 87 [2] 83 ab [2] ad 89 [2] b9 92 [2] b6 88 [2] a8 95 [2] aa 94 [2] b1 92 [2] ad 95 [2] b1 ba }

  condition:
    any of them
}