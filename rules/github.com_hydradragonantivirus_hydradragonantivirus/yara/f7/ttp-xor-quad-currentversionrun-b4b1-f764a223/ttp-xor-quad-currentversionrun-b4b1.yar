rule TTP_XOR_QUAD_CurrentVersionRun_b4b1 {
  strings:
    $key_b4b1 = { e7 de [2] c3 d0 [2] e8 fc [2] c6 de [2] d2 c5 [2] dd df [2] c3 c2 [2] c1 c3 [2] da c5 [2] c6 c2 [2] da ed }

  condition:
    any of them
}