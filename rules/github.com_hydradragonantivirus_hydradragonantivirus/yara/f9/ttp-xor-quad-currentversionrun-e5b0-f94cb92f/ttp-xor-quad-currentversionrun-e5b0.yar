rule TTP_XOR_QUAD_CurrentVersionRun_e5b0 {
  strings:
    $key_e5b0 = { b6 df [2] 92 d1 [2] b9 fd [2] 97 df [2] 83 c4 [2] 8c de [2] 92 c3 [2] 90 c2 [2] 8b c4 [2] 97 c3 [2] 8b ec }

  condition:
    any of them
}