rule TTP_XOR_QUAD_CurrentVersionRun_afb0 {
  strings:
    $key_afb0 = { fc df [2] d8 d1 [2] f3 fd [2] dd df [2] c9 c4 [2] c6 de [2] d8 c3 [2] da c2 [2] c1 c4 [2] dd c3 [2] c1 ec }

  condition:
    any of them
}