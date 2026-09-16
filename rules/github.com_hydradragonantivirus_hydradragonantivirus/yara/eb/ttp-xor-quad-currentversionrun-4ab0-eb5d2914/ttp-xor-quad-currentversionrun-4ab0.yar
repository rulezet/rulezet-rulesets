rule TTP_XOR_QUAD_CurrentVersionRun_4ab0 {
  strings:
    $key_4ab0 = { 19 df [2] 3d d1 [2] 16 fd [2] 38 df [2] 2c c4 [2] 23 de [2] 3d c3 [2] 3f c2 [2] 24 c4 [2] 38 c3 [2] 24 ec }

  condition:
    any of them
}