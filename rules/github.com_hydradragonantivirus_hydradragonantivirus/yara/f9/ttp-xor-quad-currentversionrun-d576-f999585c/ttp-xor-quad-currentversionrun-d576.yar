rule TTP_XOR_QUAD_CurrentVersionRun_d576 {
  strings:
    $key_d576 = { 86 19 [2] a2 17 [2] 89 3b [2] a7 19 [2] b3 02 [2] bc 18 [2] a2 05 [2] a0 04 [2] bb 02 [2] a7 05 [2] bb 2a }

  condition:
    any of them
}