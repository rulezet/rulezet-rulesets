rule TTP_XOR_QUAD_CurrentVersionRun_43b0 {
  strings:
    $key_43b0 = { 10 df [2] 34 d1 [2] 1f fd [2] 31 df [2] 25 c4 [2] 2a de [2] 34 c3 [2] 36 c2 [2] 2d c4 [2] 31 c3 [2] 2d ec }

  condition:
    any of them
}