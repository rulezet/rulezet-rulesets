rule TTP_XOR_QUAD_CurrentVersionRun_aab0 {
  strings:
    $key_aab0 = { f9 df [2] dd d1 [2] f6 fd [2] d8 df [2] cc c4 [2] c3 de [2] dd c3 [2] df c2 [2] c4 c4 [2] d8 c3 [2] c4 ec }

  condition:
    any of them
}