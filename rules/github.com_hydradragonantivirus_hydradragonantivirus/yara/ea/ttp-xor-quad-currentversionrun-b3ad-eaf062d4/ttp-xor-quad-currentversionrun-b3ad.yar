rule TTP_XOR_QUAD_CurrentVersionRun_b3ad {
  strings:
    $key_b3ad = { e0 c2 [2] c4 cc [2] ef e0 [2] c1 c2 [2] d5 d9 [2] da c3 [2] c4 de [2] c6 df [2] dd d9 [2] c1 de [2] dd f1 }

  condition:
    any of them
}