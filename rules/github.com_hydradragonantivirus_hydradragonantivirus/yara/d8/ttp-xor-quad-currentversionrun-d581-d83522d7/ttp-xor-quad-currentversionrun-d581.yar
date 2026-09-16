rule TTP_XOR_QUAD_CurrentVersionRun_d581 {
  strings:
    $key_d581 = { 86 ee [2] a2 e0 [2] 89 cc [2] a7 ee [2] b3 f5 [2] bc ef [2] a2 f2 [2] a0 f3 [2] bb f5 [2] a7 f2 [2] bb dd }

  condition:
    any of them
}