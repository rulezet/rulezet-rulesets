rule TTP_XOR_QUAD_CurrentVersionRun_ac93 {
  strings:
    $key_ac93 = { ff fc [2] db f2 [2] f0 de [2] de fc [2] ca e7 [2] c5 fd [2] db e0 [2] d9 e1 [2] c2 e7 [2] de e0 [2] c2 cf }

  condition:
    any of them
}