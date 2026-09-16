rule TTP_XOR_QUAD_CurrentVersionRun_ac87 {
  strings:
    $key_ac87 = { ff e8 [2] db e6 [2] f0 ca [2] de e8 [2] ca f3 [2] c5 e9 [2] db f4 [2] d9 f5 [2] c2 f3 [2] de f4 [2] c2 db }

  condition:
    any of them
}