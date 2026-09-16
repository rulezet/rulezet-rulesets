rule TTP_XOR_QUAD_CurrentVersionRun_6cb0 {
  strings:
    $key_6cb0 = { 3f df [2] 1b d1 [2] 30 fd [2] 1e df [2] 0a c4 [2] 05 de [2] 1b c3 [2] 19 c2 [2] 02 c4 [2] 1e c3 [2] 02 ec }

  condition:
    any of them
}