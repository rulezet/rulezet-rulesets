rule TTP_XOR_QUAD_CurrentVersionRun_edb0 {
  strings:
    $key_edb0 = { be df [2] 9a d1 [2] b1 fd [2] 9f df [2] 8b c4 [2] 84 de [2] 9a c3 [2] 98 c2 [2] 83 c4 [2] 9f c3 [2] 83 ec }

  condition:
    any of them
}