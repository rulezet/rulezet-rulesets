rule TTP_XOR_QUAD_CurrentVersionRun_d493 {
  strings:
    $key_d493 = { 87 fc [2] a3 f2 [2] 88 de [2] a6 fc [2] b2 e7 [2] bd fd [2] a3 e0 [2] a1 e1 [2] ba e7 [2] a6 e0 [2] ba cf }

  condition:
    any of them
}