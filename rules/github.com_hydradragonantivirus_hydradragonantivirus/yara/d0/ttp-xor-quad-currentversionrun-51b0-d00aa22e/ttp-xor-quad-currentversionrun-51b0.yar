rule TTP_XOR_QUAD_CurrentVersionRun_51b0 {
  strings:
    $key_51b0 = { 02 df [2] 26 d1 [2] 0d fd [2] 23 df [2] 37 c4 [2] 38 de [2] 26 c3 [2] 24 c2 [2] 3f c4 [2] 23 c3 [2] 3f ec }

  condition:
    any of them
}