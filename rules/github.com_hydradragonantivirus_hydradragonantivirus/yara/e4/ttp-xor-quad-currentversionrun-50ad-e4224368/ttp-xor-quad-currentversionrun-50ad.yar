rule TTP_XOR_QUAD_CurrentVersionRun_50ad {
  strings:
    $key_50ad = { 03 c2 [2] 27 cc [2] 0c e0 [2] 22 c2 [2] 36 d9 [2] 39 c3 [2] 27 de [2] 25 df [2] 3e d9 [2] 22 de [2] 3e f1 }

  condition:
    any of them
}