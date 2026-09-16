rule TTP_XOR_QUAD_CurrentVersionRun_b3b1 {
  strings:
    $key_b3b1 = { e0 de [2] c4 d0 [2] ef fc [2] c1 de [2] d5 c5 [2] da df [2] c4 c2 [2] c6 c3 [2] dd c5 [2] c1 c2 [2] dd ed }

  condition:
    any of them
}