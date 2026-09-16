rule TTP_XOR_QUAD_CurrentVersionRun_b9b0 {
  strings:
    $key_b9b0 = { ea df [2] ce d1 [2] e5 fd [2] cb df [2] df c4 [2] d0 de [2] ce c3 [2] cc c2 [2] d7 c4 [2] cb c3 [2] d7 ec }

  condition:
    any of them
}