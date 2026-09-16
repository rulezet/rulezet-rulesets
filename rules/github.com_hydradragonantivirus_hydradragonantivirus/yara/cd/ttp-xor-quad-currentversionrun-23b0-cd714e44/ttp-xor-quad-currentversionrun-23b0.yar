rule TTP_XOR_QUAD_CurrentVersionRun_23b0 {
  strings:
    $key_23b0 = { 70 df [2] 54 d1 [2] 7f fd [2] 51 df [2] 45 c4 [2] 4a de [2] 54 c3 [2] 56 c2 [2] 4d c4 [2] 51 c3 [2] 4d ec }

  condition:
    any of them
}