rule TTP_XOR_QUAD_CurrentVersionRun_36ad {
  strings:
    $key_36ad = { 65 c2 [2] 41 cc [2] 6a e0 [2] 44 c2 [2] 50 d9 [2] 5f c3 [2] 41 de [2] 43 df [2] 58 d9 [2] 44 de [2] 58 f1 }

  condition:
    any of them
}