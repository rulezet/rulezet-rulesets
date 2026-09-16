rule TTP_XOR_QUAD_CurrentVersionRun_d8b0 {
  strings:
    $key_d8b0 = { 8b df [2] af d1 [2] 84 fd [2] aa df [2] be c4 [2] b1 de [2] af c3 [2] ad c2 [2] b6 c4 [2] aa c3 [2] b6 ec }

  condition:
    any of them
}