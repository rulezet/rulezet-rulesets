rule TTP_XOR_QUAD_CurrentVersionRun_3cad {
  strings:
    $key_3cad = { 6f c2 [2] 4b cc [2] 60 e0 [2] 4e c2 [2] 5a d9 [2] 55 c3 [2] 4b de [2] 49 df [2] 52 d9 [2] 4e de [2] 52 f1 }

  condition:
    any of them
}