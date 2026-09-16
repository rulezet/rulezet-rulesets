rule TTP_XOR_QUAD_CurrentVersionRun_d2e6 {
  strings:
    $key_d2e6 = { 81 89 [2] a5 87 [2] 8e ab [2] a0 89 [2] b4 92 [2] bb 88 [2] a5 95 [2] a7 94 [2] bc 92 [2] a0 95 [2] bc ba }

  condition:
    any of them
}