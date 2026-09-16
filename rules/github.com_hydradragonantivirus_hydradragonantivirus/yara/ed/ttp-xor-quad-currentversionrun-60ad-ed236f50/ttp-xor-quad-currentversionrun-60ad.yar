rule TTP_XOR_QUAD_CurrentVersionRun_60ad {
  strings:
    $key_60ad = { 33 c2 [2] 17 cc [2] 3c e0 [2] 12 c2 [2] 06 d9 [2] 09 c3 [2] 17 de [2] 15 df [2] 0e d9 [2] 12 de [2] 0e f1 }

  condition:
    any of them
}