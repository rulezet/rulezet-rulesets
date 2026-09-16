rule TTP_XOR_QUAD_CurrentVersionRun_d2b3 {
  strings:
    $key_d2b3 = { 81 dc [2] a5 d2 [2] 8e fe [2] a0 dc [2] b4 c7 [2] bb dd [2] a5 c0 [2] a7 c1 [2] bc c7 [2] a0 c0 [2] bc ef }

  condition:
    any of them
}