rule TTP_XOR_QUAD_CurrentVersionRun_d591 {
  strings:
    $key_d591 = { 86 fe [2] a2 f0 [2] 89 dc [2] a7 fe [2] b3 e5 [2] bc ff [2] a2 e2 [2] a0 e3 [2] bb e5 [2] a7 e2 [2] bb cd }

  condition:
    any of them
}