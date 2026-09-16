rule TTP_XOR_QUAD_CurrentVersionRun_d5e0 {
  strings:
    $key_d5e0 = { 86 8f [2] a2 81 [2] 89 ad [2] a7 8f [2] b3 94 [2] bc 8e [2] a2 93 [2] a0 92 [2] bb 94 [2] a7 93 [2] bb bc }

  condition:
    any of them
}