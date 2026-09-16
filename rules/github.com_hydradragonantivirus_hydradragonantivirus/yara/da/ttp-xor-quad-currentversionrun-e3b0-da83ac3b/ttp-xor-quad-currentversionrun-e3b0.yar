rule TTP_XOR_QUAD_CurrentVersionRun_e3b0 {
  strings:
    $key_e3b0 = { b0 df [2] 94 d1 [2] bf fd [2] 91 df [2] 85 c4 [2] 8a de [2] 94 c3 [2] 96 c2 [2] 8d c4 [2] 91 c3 [2] 8d ec }

  condition:
    any of them
}