rule TTP_XOR_QUAD_CurrentVersionRun_c98d {
  strings:
    $key_c98d = { 9a e2 [2] be ec [2] 95 c0 [2] bb e2 [2] af f9 [2] a0 e3 [2] be fe [2] bc ff [2] a7 f9 [2] bb fe [2] a7 d1 }

  condition:
    any of them
}