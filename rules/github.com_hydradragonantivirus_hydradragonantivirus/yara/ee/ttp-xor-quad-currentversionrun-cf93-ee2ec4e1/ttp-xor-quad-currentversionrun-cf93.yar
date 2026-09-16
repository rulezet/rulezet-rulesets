rule TTP_XOR_QUAD_CurrentVersionRun_cf93 {
  strings:
    $key_cf93 = { 9c fc [2] b8 f2 [2] 93 de [2] bd fc [2] a9 e7 [2] a6 fd [2] b8 e0 [2] ba e1 [2] a1 e7 [2] bd e0 [2] a1 cf }

  condition:
    any of them
}