rule TTP_XOR_QUAD_CurrentVersionRun_22ad {
  strings:
    $key_22ad = { 71 c2 [2] 55 cc [2] 7e e0 [2] 50 c2 [2] 44 d9 [2] 4b c3 [2] 55 de [2] 57 df [2] 4c d9 [2] 50 de [2] 4c f1 }

  condition:
    any of them
}