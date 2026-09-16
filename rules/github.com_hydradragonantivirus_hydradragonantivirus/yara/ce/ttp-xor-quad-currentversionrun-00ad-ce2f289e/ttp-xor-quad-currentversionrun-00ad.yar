rule TTP_XOR_QUAD_CurrentVersionRun_00ad {
  strings:
    $key_00ad = { 53 c2 [2] 77 cc [2] 5c e0 [2] 72 c2 [2] 66 d9 [2] 69 c3 [2] 77 de [2] 75 df [2] 6e d9 [2] 72 de [2] 6e f1 }

  condition:
    any of them
}