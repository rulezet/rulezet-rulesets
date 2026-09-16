rule TTP_XOR_QUAD_CurrentVersionRun_3db0 {
  strings:
    $key_3db0 = { 6e df [2] 4a d1 [2] 61 fd [2] 4f df [2] 5b c4 [2] 54 de [2] 4a c3 [2] 48 c2 [2] 53 c4 [2] 4f c3 [2] 53 ec }

  condition:
    any of them
}